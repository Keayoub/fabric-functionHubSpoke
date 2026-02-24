"""
=============================================================
Azure Function App - Fabric Hub & Spoke Token Broker (v2)
=============================================================
Centralized Service Principal token broker for Fabric workspaces.
Supports both interactive users and pipeline/Spark MSI callers.
=============================================================
"""

import logging
import os
import json
import time
from typing import Optional

import azure.functions as func
from azure.identity import ManagedIdentityCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from msal import ConfidentialClientApplication
import jwt
from cryptography.hazmat.primitives import serialization
import requests as http_req

logger = logging.getLogger(__name__)

# ─── ENV VARS ──────────────────────────────────────────────────────
def _get_env_var(key, default=None):
    """Get environment variable with fallback and logging."""
    value = os.environ.get(key, default)
    if value is None:
        logger.warning(f"Environment variable '{key}' not found")
    return value


TENANT_ID = _get_env_var("ENTRA_TENANT_ID", "")
FUNC_APP_CLIENT_ID = _get_env_var("FUNC_APP_CLIENT_ID", "")
KEY_VAULT_URL = _get_env_var("KEY_VAULT_URL", "")
SP_CLIENT_ID_SECRET = _get_env_var("SP_CLIENT_ID_SECRET_NAME", "sp-client-id")
SP_CLIENT_SECRET_NAME = _get_env_var("SP_CLIENT_SECRET_NAME", "sp-client-secret")
SP_TENANT_SECRET = _get_env_var("SP_TENANT_ID_SECRET_NAME", "sp-tenant-id")
ALLOWED_MSI_SECRET = _get_env_var("ALLOWED_MSI_OIDS_SECRET_NAME", "allowed-msi-oids")
# ───────────────────────────────────────────────────────────────────

JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# ── Module-level caches (survive warm Function instances) ──────────
_jwks_cache: dict = {}  # {"keys": [...], "fetched_at": float}
_JWKS_TTL_SECONDS: int = 3600  # refresh JWKS every hour
_msal_apps: dict = {}  # { sp_client_id: ConfidentialClientApplication } — one per SP
# ───────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════
# SECTION 1 — JWKS (cached)
# ══════════════════════════════════════════════════════════════════
def _get_jwks() -> dict:
    """
    Return JWKS from Entra ID, using module-level cache with 1-hour TTL.
    Avoids hammering Entra ID on every Function invocation.
    """
    global _jwks_cache
    now = time.time()

    if _jwks_cache and (now - _jwks_cache.get("fetched_at", 0)) < _JWKS_TTL_SECONDS:
        return _jwks_cache

    logger.info("Refreshing JWKS from Entra ID")
    resp = http_req.get(JWKS_URI, timeout=10)
    resp.raise_for_status()
    _jwks_cache = {**resp.json(), "fetched_at": now}
    return _jwks_cache


# ══════════════════════════════════════════════════════════════════
# SECTION 2 — JWT VALIDATION
# ══════════════════════════════════════════════════════════════════
def validate_token(auth_header: str) -> dict:
    """
    Validate Bearer JWT from Fabric (user or MSI).
    Returns decoded claims dict on success.
    Raises ValueError on any validation failure.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise ValueError("Missing or malformed Authorization header")

    token = auth_header[7:]

    # Get kid from token header (unverified — only used to pick the right key)
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except Exception as e:
        raise ValueError(f"Cannot read token header: {e}")

    if not kid:
        raise ValueError("Token header missing 'kid'")

    # Find matching key in JWKS
    jwks = _get_jwks()
    matching = [k for k in jwks.get("keys", []) if k.get("kid") == kid]

    # If kid not found, force-refresh JWKS once (key rotation edge case)
    if not matching:
        logger.warning("kid=%s not found in cache — forcing JWKS refresh", kid)
        global _jwks_cache
        _jwks_cache = {}
        jwks = _get_jwks()
        matching = [k for k in jwks.get("keys", []) if k.get("kid") == kid]

    if not matching:
        raise ValueError(f"No JWKS key found for kid={kid}")

    # Convert JWKS key to PEM format for PyJWT
    jwks_key = matching[0]
    public_key_pem = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks_key))

    # Verify and decode — PyJWT checks exp, nbf, iss, aud automatically
    claims = jwt.decode(
        token,
        key=public_key_pem,
        algorithms=["RS256"],
        audience=f"api://{FUNC_APP_CLIENT_ID}",
        issuer=ISSUER,
        options={
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "verify_aud": True,
        },
    )
    return claims


# ══════════════════════════════════════════════════════════════════
# SECTION 3 — CALLER IDENTITY RESOLUTION
# ══════════════════════════════════════════════════════════════════
def resolve_caller(claims: dict) -> dict:
    """
    Determine WHO is calling — a real user or a pipeline/Spark MSI.

    Returns a structured caller info dict:
    {
        "type":         "USER" | "MSI",
        "oid":          str,        # stable unique ID — use for authz/audit
        "display":      str,        # upn for users, appid for MSI
        "upn":          str | None, # only for real users
        "appid":        str | None, # Fabric app or workspace MSI client ID
        "is_pipeline":  bool
    }

    Detection logic:
    - Presence of "upn" or "preferred_username" → real interactive user
    - Absence of "upn" + presence of "appid" without "scp" → MSI / pipeline
    """
    upn = claims.get("upn") or claims.get("preferred_username")
    oid = claims.get("oid", "unknown")
    appid = claims.get("appid") or claims.get("azp")
    scp = claims.get("scp", "")  # scp (delegated scope) only present for users

    is_user = bool(upn) or bool(scp)

    caller = {
        "type": "USER" if is_user else "MSI",
        "oid": oid,
        "display": upn if is_user else appid,
        "upn": upn,
        "appid": appid,
        "is_pipeline": not is_user,
        "tid": claims.get("tid", TENANT_ID),
    }

    logger.info(
        "Caller resolved — type=%s display=%s oid=%s",
        caller["type"],
        caller["display"],
        caller["oid"],
    )
    return caller


# ══════════════════════════════════════════════════════════════════
# SECTION 4 — AUTHORIZATION
# ══════════════════════════════════════════════════════════════════
def _get_kv_client() -> SecretClient:
    """Return a Key Vault client using appropriate credentials."""
    if not KEY_VAULT_URL:
        raise ValueError("KEY_VAULT_URL not configured")
    
    # In local development: use DefaultAzureCredential (which tries CLI, env vars, etc.)
    # In Azure: use ManagedIdentityCredential
    is_local_dev = not os.environ.get("WEBSITE_INSTANCE_ID")

    if is_local_dev:
        logger.info("Using DefaultAzureCredential for local development")
        credential = DefaultAzureCredential()
    else:
        logger.info("Using ManagedIdentityCredential for Azure")
        credential = ManagedIdentityCredential()

    return SecretClient(vault_url=KEY_VAULT_URL, credential=credential)


def authorize_caller(caller: dict, kv: SecretClient) -> None:
    """
    Authorization rules:
    - USER    → always allowed if JWT is valid (Entra handles user AuthN)
    - MSI     → must have OID in the whitelist stored in Key Vault

    The whitelist is a JSON array stored as a KV secret:
    Key   : allowed-msi-oids
    Value : ["oid-workspace-hub", "oid-workspace-spoke-a", "oid-workspace-spoke-b"]

    Hub admins add/remove OIDs in Key Vault — zero Function redeployment needed.
    """
    if caller["type"] == "USER":
        # Real user — JWT validation is sufficient
        # Add extra checks here if needed (e.g. group membership, specific UPN domain)
        return

    # MSI / Pipeline — check OID whitelist
    try:
        if not ALLOWED_MSI_SECRET:
            raise ValueError("ALLOWED_MSI_SECRET not configured")
        whitelist_raw = kv.get_secret(ALLOWED_MSI_SECRET).value
        if not whitelist_raw:
            raise ValueError("MSI whitelist secret is empty")
        allowed_oids = json.loads(whitelist_raw)  # expects a JSON array of strings
    except Exception as e:
        logger.error("Failed to read MSI whitelist from KV: %s", e)
        raise PermissionError(
            "MSI authorization whitelist unavailable — cannot authorize pipeline caller"
        )

    caller_oid = caller["oid"]

    # Check if wildcard "*" is in the list (allow all) or specific OID is present
    if "*" not in allowed_oids and caller_oid not in allowed_oids:
        logger.warning(
            "UNAUTHORIZED MSI — oid=%s not in whitelist. "
            "Add this OID to the '%s' secret in Key Vault to allow it.",
            caller_oid,
            ALLOWED_MSI_SECRET,
        )
        raise PermissionError(
            f"MSI oid={caller_oid} is not in the allowed list. "
            f"Contact your Hub workspace admin to add it."
        )

    logger.info("MSI authorized — oid=%s", caller_oid)

# ══════════════════════════════════════════════════════════════════
# SECTION 5 — KEY VAULT: SP CREDENTIALS
# ══════════════════════════════════════════════════════════════════
def get_sp_creds(kv: SecretClient, sp_name: Optional[str] = None) -> tuple[str, str, str]:
    """
    Fetch SP credentials from Key Vault using Function Managed Identity.
    Returns (sp_client_id, sp_client_secret, sp_tenant_id).

    If sp_name is provided, secrets are resolved by convention:
        {sp_name}-client-id      → client ID
        {sp_name}-client-secret  → client secret
        {sp_name}-tenant-id      → tenant (optional, falls back to ENTRA_TENANT_ID)

    If sp_name is omitted, falls back to env-var-configured secret names
    (SP_CLIENT_ID_SECRET_NAME, SP_CLIENT_SECRET_NAME, SP_TENANT_ID_SECRET_NAME).
    """
    if sp_name:
        client_id_secret_name: str = f"{sp_name}-client-id"
        client_secret_secret_name: str = f"{sp_name}-client-secret"
        tenant_secret_name: str = f"{sp_name}-tenant-id"
    else:
        client_id_secret_name = SP_CLIENT_ID_SECRET or "sp-client-id"
        client_secret_secret_name = SP_CLIENT_SECRET_NAME or "sp-client-secret"
        tenant_secret_name = SP_TENANT_SECRET or "sp-tenant-id"

    try:
        sp_id_secret = kv.get_secret(client_id_secret_name)
        if not sp_id_secret or not sp_id_secret.value:
            raise ValueError(f"SP client-id secret '{client_id_secret_name}' is empty")
        sp_id = sp_id_secret.value
    except Exception as e:
        logger.error("Failed to fetch SP client-id from KV (secret=%s): %s", client_id_secret_name, e)
        raise

    try:
        sp_secret_secret = kv.get_secret(client_secret_secret_name)
        if not sp_secret_secret or not sp_secret_secret.value:
            raise ValueError(f"SP client-secret secret '{client_secret_secret_name}' is empty")
        sp_secret = sp_secret_secret.value
    except Exception as e:
        logger.error("Failed to fetch SP client-secret from KV (secret=%s): %s", client_secret_secret_name, e)
        raise

    try:
        sp_tid_secret = kv.get_secret(tenant_secret_name)
        sp_tid: str = (sp_tid_secret.value or TENANT_ID or "") if sp_tid_secret else (TENANT_ID or "")
    except Exception:
        sp_tid = TENANT_ID or ""

    logger.info(
        "SP creds fetched from KV — sp_name=%s sp_client_id=%s...",
        sp_name or "(default)",
        sp_id[:8] if len(sp_id) > 8 else sp_id,
    )
    return sp_id, sp_secret, sp_tid


# ══════════════════════════════════════════════════════════════════
# SECTION 6 — SP TOKEN (MSAL, cached)
# ══════════════════════════════════════════════════════════════════
def get_sp_token(
    sp_client_id: str, sp_client_secret: str, sp_tenant_id: str, target_scope: str
) -> dict:
    """
    Get SP access token via client_credentials flow.
    MSAL ConfidentialClientApplication instances are cached per sp_client_id —
    one entry per SP, reused across warm Function invocations.
    """
    global _msal_apps

    # Lazy-init per-SP MSAL app (keyed by client_id)
    if sp_client_id not in _msal_apps:
        _msal_apps[sp_client_id] = ConfidentialClientApplication(
            client_id=sp_client_id,
            client_credential=sp_client_secret,
            authority=f"https://login.microsoftonline.com/{sp_tenant_id}",
        )

    msal_app = _msal_apps[sp_client_id]

    scope = (
        target_scope
        if target_scope.endswith("/.default")
        else target_scope.rstrip("/") + "/.default"
    )

    # acquire_token_for_client checks the cache first — only calls Entra if expired
    result: Optional[dict] = msal_app.acquire_token_for_client(scopes=[scope])

    if not result:
        raise RuntimeError("MSAL returned empty result")

    if "error" in result:
        raise RuntimeError(
            f"MSAL error: {result.get('error', 'unknown')} — {result.get('error_description', '')}"
        )

    logger.info("SP token ready — expires_in=%ss", result.get("expires_in"))
    return result


# ══════════════════════════════════════════════════════════════════
# SECTION 7 — HTTP TRIGGER (Python v2 Programming Model)
# ══════════════════════════════════════════════════════════════════
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    return func.HttpResponse(
        json.dumps({"status": "ok", "message": "Azure Function is running"}),
        status_code=200,
        mimetype="application/json",
    )


@app.route(route="GetSPToken", methods=["POST"])
def get_sp_token_handler(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP POST endpoint: /api/GetSPToken

    Request:
    {
        "targetScope": "https://management.azure.com/.default"
    }

    Response (200):
    {
        "access_token": "...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "...",
        "caller": {
            "type": "USER" | "MSI",
            "oid": "...",
            "display": "...",
            "is_pipeline": false
        }
    }
    """
    logger.info("GetSPToken triggered")

    # ── Step 1: Validate JWT (skip in local development) ──────────
    # Check if running locally (no WEBSITE_INSTANCE_ID = local, set = Azure App Service)
    is_local_dev = not os.environ.get("WEBSITE_INSTANCE_ID")

    if is_local_dev:
        logger.info("LOCAL DEV MODE: Skipping JWT validation")
        # For local testing, create a minimal caller object
        caller = {
            "type": "USER",
            "oid": "local-test-user",
            "display": "local-dev@test.com",
            "upn": "local-dev@test.com",
            "appid": None,
            "is_pipeline": False,
            "tid": TENANT_ID,
        }
    else:
        # Production: validate JWT
        try:
            claims = validate_token(req.headers.get("Authorization", ""))
        except (ValueError, Exception) as e:
            logger.warning("Token validation failed: %s", e)
            return _error(401, "unauthorized", str(e))

        # ── Step 2: Resolve caller identity ──────────────────────────
        caller = resolve_caller(claims)

    # ── Step 3: KV client (single connection reused for both authz + creds) ──
    try:
        kv = _get_kv_client()
    except Exception as e:
        logger.error("KV client init failed: %s", e)
        return _error(500, "keyvault_error", str(e))

    # ── Step 4: Authorize the caller (skip in local dev) ────────────
    if not is_local_dev:
        try:
            authorize_caller(caller, kv)
        except PermissionError as e:
            return _error(403, "forbidden", str(e))
        except Exception as e:
            logger.error("Authorization error: %s", e)
            return _error(500, "authorization_error", str(e))

    # ── Step 5: Parse request body ────────────────────────────────
    try:
        body = req.get_json()
        target_scope = body.get("targetScope", "https://management.azure.com/.default")
        # spName selects which SP to use (must match KV secret prefix).
        # If omitted, falls back to the default SP configured via env vars.
        sp_name: Optional[str] = body.get("spName")  # e.g. "fabric-synapse-sp"
    except Exception:
        target_scope = "https://management.azure.com/.default"
        sp_name = None

    # ── Step 6: Fetch SP credentials from KV ─────────────────────
    try:
        sp_id, sp_secret, sp_tid = get_sp_creds(kv, sp_name=sp_name)
    except Exception as e:
        logger.error("KV secret fetch failed (sp_name=%s): %s", sp_name, e)
        return _error(500, "keyvault_error", str(e))

    # ── Step 7: Acquire SP token ──────────────────────────────────
    try:
        tok = get_sp_token(sp_id, sp_secret, sp_tid, target_scope)
    except RuntimeError as e:
        logger.error("SP token error: %s", e)
        return _error(500, "token_error", str(e))

    # ── Step 8: Return SP token + full caller audit info ──────────
    response = {
        # SP token for downstream use
        "access_token": tok["access_token"],
        "token_type": tok.get("token_type", "Bearer"),
        "expires_in": tok.get("expires_in", 3600),
        "scope": tok.get("scope", target_scope),
        # Caller audit metadata
        "caller": {
            "type": caller["type"],  # "USER" or "MSI"
            "oid": caller["oid"],  # stable Entra object ID
            "display": caller["display"],  # upn for users, appid for MSI
            "is_pipeline": caller["is_pipeline"],  # True = pipeline/Spark
        },
    }

    response["sp_name"] = sp_name or "(default)"

    logger.info(
        "SP token returned — caller_type=%s caller=%s sp_name=%s scope=%s",
        caller["type"],
        caller["display"],
        sp_name or "(default)",
        target_scope,
    )
    return func.HttpResponse(
        json.dumps(response), status_code=200, mimetype="application/json"
    )


def _error(status: int, code: str, message: str) -> func.HttpResponse:
    """Helper to return JSON error response"""
    return func.HttpResponse(
        json.dumps({"error": code, "message": message}),
        status_code=status,
        mimetype="application/json",
    )
