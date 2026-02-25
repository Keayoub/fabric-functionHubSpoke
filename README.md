# Fabric Hub & Spoke - Azure Function Token Broker

Centralized Service Principal token broker for Microsoft Fabric workspaces with **OAP (Outbound Access Policies)** enabled.

## 🎯 Problem Solved

When OAP is enabled in Fabric, notebooks **cannot call `login.microsoftonline.com` directly**. This Function App acts as a token broker that:
- Sits outside Fabric (unrestricted Entra ID access)
- Is reachable from Fabric via **MPE (Managed Private Endpoint)**
- Returns Service Principal tokens for any Azure resource

## 🏗️ Architecture

```
┌─────────────── HUB ──────────────────┐
│  Azure Function + Key Vault          │
│  - SP credentials in Key Vault       │
│  - Whitelist-based MSI authorization │
│  - JWT validation (both USER & MSI)  │
└──────────────┬───────────────────────┘
               │  (via MPE)
    ┌──────────┴──────────┐
    │                     │
[Spoke A]            [Spoke B]
Workspace           Workspace
- Notebooks         - Pipelines
- Pipelines         - Spark Jobs
```

## 🎯 Features

✅ **OAP Bypass**: Fabric calls Function → Function calls Entra → Token returned  
✅ **Dual Caller Support**: Works for both interactive users AND automated pipelines (MSI)  
✅ **Zero Credential Sprawl**: SP credentials stored only in Key Vault  
✅ **Easy Onboarding**: Add workspace MSI OID to whitelist—no redeployment  
✅ **Full Audit Trail**: Logs every request with caller identity  
✅ **Flexible Audience**: Accepts both `api://CLIENT_ID` and `CLIENT_ID` token formats  
✅ **Enterprise Security**: JWT validation with JWKS caching + key rotation support  

## 📁 Project Structure

```
fabric-functionHubSpoke/
├── function_app.py                    # Main Function App (Python v2 model)
├── host.json                          # Function host configuration
├── requirements.txt                   # Python dependencies
├── local.settings.json.example        # Template for local development settings
├── deploy.ps1                         # Deployment script for Azure
│
├── scripts/
│   └── setup_sp_keyvault.ps1         # Script to bootstrap Key Vault secrets
│
├── samples/
│   ├── call_function_sample.ipynb    # Example notebook calling the function
│   └── test_function.ipynb           # Testing notebook
│
├── README.md                          # This file
└── requirements.txt                  # Python dependencies
```

## 🚀 Deployment

### Prerequisites

1. **Azure CLI** installed and logged in
2. **Python 3.12** with Azure Functions Core Tools v4
3. **Service Principal** with appropriate Azure resource permissions
4. **Entra App Registration** for the Function App (see step below)

### Step 1: Create Azure Function App

This project uses **Python 3.12** with the **v2 programming model** (`@app.route()` decorators).

```powershell
# Variables (update these)
$RESOURCE_GROUP = "Fabric-Demos"
$LOCATION = "eastus2"
$FUNCTION_APP = "fabricmpeapis"
$KEY_VAULT = "kaydemokeyvault"

# Create Function App (Flex Consumption recommended for cost efficiency)
az functionapp create `
  --name $FUNCTION_APP `
  --resource-group $RESOURCE_GROUP `
  --runtime python `
  --runtime-version 3.12 `
  --functions-version 4 `
  --os-type Linux `
  --assign-identity [system]
```

### Step 2: Configure Entra App Registration (CRITICAL)

**This step is mandatory** or `mssparkutils.credentials.getToken()` will fail with 500 error.

1. **Azure Portal → Entra ID → App registrations → Create new registration**
   - Name: Same as Function App name (e.g., `fabricmpeapis`)
   - Supported account types: Single tenant
   - Click **Register**

2. **Expose an API → Add Application ID URI**
   - Accept default: `api://<client-id>`
   
3. **Add a scope**:
   - Scope name: `user_impersonation`
   - Who can consent: **Admins and users**
   - Admin display name: `Access fabricmpeapis`
   - State: **Enabled**

4. **(Optional) Pre-authorize Fabric workspace MSI**:
   - Under **Authorized client applications**, add workspace MSI app ID
   - This skips consent prompt for MSI callers

5. **Copy the Client ID** (you'll need it in the next step)

### Step 3: Configure Function App Settings

⚠️ **CRITICAL**: The `AzureWebJobsFeatureFlags` setting is **required** for Python v2 model with decorators, or your functions won't appear in the portal.

```powershell
$TENANT_ID = az account show --query tenantId -o tsv
$KV_URL = "https://$KEY_VAULT.vault.azure.net/"
$CLIENT_ID = "<entra-app-registration-client-id-from-step-2>"

# Set all required Function App settings
az functionapp config appsettings set `
  --name $FUNCTION_APP `
  --resource-group $RESOURCE_GROUP `
  --settings `
    ENTRA_TENANT_ID=$TENANT_ID `
    FUNC_APP_CLIENT_ID=$CLIENT_ID `
    KEY_VAULT_URL=$KV_URL `
    AzureWebJobsFeatureFlags=EnableWorkerIndexing
```

### Step 4: Grant Function MSI Access to Key Vault

```powershell
$FUNCTION_PRINCIPAL_ID = az functionapp identity show `
  --name $FUNCTION_APP `
  --resource-group $RESOURCE_GROUP `
  --query principalId -o tsv

$KV_SCOPE = az keyvault show `
  --name $KEY_VAULT `
  --query id -o tsv

# Grant "Key Vault Secrets User" role
az role assignment create `
  --role "Key Vault Secrets User" `
  --assignee $FUNCTION_PRINCIPAL_ID `
  --scope $KV_SCOPE
```

### Step 5: Store SP Credentials in Key Vault

Store your Service Principal credentials in Key Vault:

```powershell
# Add SP credentials
az keyvault secret set --vault-name $KEY_VAULT --name "sp-client-id" --value "<your-sp-client-id>"
az keyvault secret set --vault-name $KEY_VAULT --name "sp-client-secret" --value "<your-sp-client-secret>"
az keyvault secret set --vault-name $KEY_VAULT --name "sp-tenant-id" --value "<your-sp-tenant-id>"

# Whitelist Fabric workspace MSI OIDs (JSON array format)
# Find OID: Fabric Workspace → Settings → License info → Workspace identity
az keyvault secret set --vault-name $KEY_VAULT --name "allowed-msi-oids" --value '["<workspace-msi-oid-1>", "<workspace-msi-oid-2>"]'
```

> **Note**: The SP must have appropriate permissions on target Azure resources (e.g., `db_datareader` on SQL databases, Reader/Contributor on subscriptions, etc.)

### Step 6: Deploy Function Code

Use the included deployment script which bundles dependencies locally:

```powershell
cd d:\fabric-functionHubSpoke
.\scripts\deploy.ps1
```

Or deploy manually using Azure Functions Core Tools:

```powershell
func azure functionapp publish $FUNCTION_APP --no-build --python
```

### Step 7: Create Managed Private Endpoint (MPE)

For Fabric notebooks to reach the Function App:

1. **Fabric Workspace → Settings → Managed Private Endpoints**
2. **Create new MPE**:
   - Target resource type: **Azure Function App**
   - Subscription: Select your subscription
   - Resource: Select your Function App (`$FUNCTION_APP`)
3. **Approve the MPE** in Azure Portal (if required by your policies)

### Step 8: Verify Deployment

Test the health endpoint:

```powershell
$FUNCTION_URL = "https://$FUNCTION_APP.azurewebsites.net"
Invoke-WebRequest -Uri "$FUNCTION_URL/api/health" -UseBasicParsing
```

Expected response:
```json
{"status": "ok", "message": "Azure Function is running"}
```

## 🧪 Local Testing

1. **Create virtual environment and install dependencies**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Create local settings file**:
   ```powershell
   Copy-Item local.settings.json.example local.settings.json
   # Edit local.settings.json with your values
   ```

3. **Start local Function runtime**:
   ```powershell
   func start
   ```

4. **Test endpoints**:
   ```powershell
   # Health check
   Invoke-WebRequest http://localhost:7071/api/health

   # Get SP token (requires valid bearer token)
   $TOKEN = "<your-test-bearer-token>"
   Invoke-WebRequest http://localhost:7071/api/GetSPToken `
     -Method POST `
     -Headers @{"Authorization"="Bearer $TOKEN"} `
     -ContentType "application/json" `
     -Body '{"targetScope": "https://database.windows.net/.default"}'
   ```

## 📝 Usage in Fabric Notebooks

See [samples/call_function_sample.ipynb](samples/call_function_sample.ipynb) for a complete, production-ready example.

### Quick Start

```python
from notebookutils import mssparkutils
import requests

FUNC_APP_CLIENT_ID = "your_function_app_ID"  # Your Function App's Entra app registration
FUNCTION_URL = "https://your_function_name.azurewebsites.net/api/GetSPToken"

# Get token to call the Function (proves your identity to the Function)
fabric_token = mssparkutils.credentials.getToken(f"api://{FUNC_APP_CLIENT_ID}")

# Call Function to get Service Principal token for target resource
response = requests.post(
    FUNCTION_URL,
    headers={"Authorization": f"Bearer {fabric_token}"},
    json={"targetScope": "https://database.windows.net/.default"}  # For Azure SQL
)

sp_token = response.json()["access_token"]
# Use sp_token to connect to Azure SQL, Azure Management API, etc.
```

### Azure SQL Connection (with SQLAlchemy - Recommended)

To avoid pandas warning about pyodbc, use SQLAlchemy:

```python
from sqlalchemy import create_engine, event
from sqlalchemy.engine.url import URL
import struct

SERVER = "your-server.database.windows.net"
DATABASE = "your-database"

# Create connection URL
connection_url = URL.create(
    "mssql+pyodbc",
    host=SERVER,
    database=DATABASE,
    query={
        "driver": "ODBC Driver 18 for SQL Server",
        "Encrypt": "yes",
        "TrustServerCertificate": "no",
    }
)

engine = create_engine(connection_url)

# Inject token before each connection
@event.listens_for(engine, "do_connect")
def provide_token(dialect, conn_rec, cargs, cparams):
    token_bytes = sp_token.encode("utf-16-le")
    token_struct = struct.pack(f"<I{len(token_bytes)}s", len(token_bytes), token_bytes)
    cparams["attrs_before"] = {1256: token_struct}  # SQL_COPT_SS_ACCESS_TOKEN

# Query using pandas
import pandas as pd
df = pd.read_sql("SELECT TOP 10 * FROM [SalesLT].[Customer]", engine)
```

### Alternative: Direct pyodbc (works but shows warning)

```python
import pyodbc
import struct

token_bytes = sp_token.encode("utf-16-le")
token_struct = struct.pack(f"<I{len(token_bytes)}s", len(token_bytes), token_bytes)

conn = pyodbc.connect(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    f"SERVER={SERVER};DATABASE={DATABASE};Encrypt=yes;",
    attrs_before={1256: token_struct}
)
df = pd.read_sql("SELECT TOP 10 * FROM YourTable", conn)
conn.close()
```

### Supported Target Scopes

| Resource | `targetScope` value |
|---|---|
| **Azure SQL / Synapse Analytics** | `https://database.windows.net/.default` |
| Azure Data Lake Storage Gen2 | `https://storage.azure.com/.default` |
| Azure Management REST API | `https://management.azure.com/.default` |
| Microsoft Graph | `https://graph.microsoft.com/.default` |
| Custom App | `api://<app-client-id>/.default` |

> **Important**: Use `api://<CLIENT_ID>` (no `/.default`) when calling `mssparkutils.credentials.getToken()`. Use `https://resource/.default` when specifying `targetScope` in the Function POST body.

## 🔐 Security Considerations

- **Managed Identity**: Function App uses system-assigned MSI to access Key Vault (no credentials in code)
- **Whitelist-based Authorization**: Only pre-approved Fabric workspace MSIs can request tokens
- **JWT Validation**: All incoming requests validated with Entra's JWKS (public key cryptography)
- **Flexible Audience**: Accepts both `api://CLIENT_ID` and `CLIENT_ID` token formats for compatibility
- **Audit Trail**: Function logs caller identity (USER email or MSI OID) with every request
- **Credential Isolation**: SP credentials never leave Key Vault; only access tokens returned
- **Key Rotation**: JWKS cache auto-refreshes on signature validation failures

## 📊 Monitoring

Enable Application Insights for the Function App to track:
- Request volume and latency per caller type
- Authorization failures (401/403)
- Token acquisition errors from MSAL
- Key Vault access errors

### Example Queries

**Requests by caller type**:
```kusto
traces
| where message contains "GetSPToken"
| extend caller_type = tostring(customDimensions.caller_type)
| where caller_type in ("USER", "MSI")
| summarize count() by bin(timestamp, 1h), caller_type
| render timechart
```

**Authorization failures**:
```kusto
traces
| where message contains "403" or message contains "401"
| project timestamp, message, customDimensions
| order by timestamp desc
```

## 🔄 Key Concepts

### Two Tokens in Every Request

| Token | Acquired by | Audience | Purpose |
|-------|-------------|----------|---------|
| **Fabric Token** | `mssparkutils.credentials.getToken()` | `api://FUNC_APP_CLIENT_ID` | Proves your identity **to the Function** |
| **SP Token** | Function → MSAL | Target resource (e.g., `https://database.windows.net/`) | Used to connect **to the actual resource** |

### The `/.default` Suffix Rule

| Call | Correct Value | Why |
|------|---------------|-----|
| `mssparkutils.credentials.getToken(audience)` | `api://<CLIENT_ID>` | Fabric Token Manager requires resource URI **without** `/.default` |
| `targetScope` in Function POST body | `https://database.windows.net/.default` | MSAL `acquire_token_for_client` requires scope **with** `/.default` |

### OAP Bypass Flow

1. ❌ Fabric **cannot** call `login.microsoftonline.com` (blocked by OAP)
2. ✅ Fabric **calls Function via MPE** (allowed network path)
3. ✅ Function **calls Entra ID** (outside Fabric, unrestricted)
4. ✅ Fabric **uses returned SP token** to connect to target resource directly

## 📚 References

- [Azure Functions Python v2 Programming Model](https://learn.microsoft.com/azure/azure-functions/functions-reference-python?pivots=python-mode-decorators)
- [Microsoft Fabric Workspace Identity](https://learn.microsoft.com/fabric/security/workspace-identity)
- [Azure Key Vault RBAC Guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [MSAL Python acquire_token_for_client](https://msal-python.readthedocs.io/en/latest/#msal.ConfidentialClientApplication.acquire_token_for_client)
- [Fabric Managed Private Endpoints](https://learn.microsoft.com/fabric/security/security-managed-private-endpoints-overview)
- [SQLAlchemy with Azure SQL](https://learn.microsoft.com/sql/connect/python/python-driver-for-sql-server)

---

## 📝 Notes

- This solution is ideal for Fabric environments with **OAP enabled** where direct Entra ID calls are blocked
- The SP stored in Key Vault must have appropriate RBAC/permissions on target Azure resources
- Function App endpoints `/api/health` and `/api/GetSPToken` are the only exposed routes
- Portal function listing may show stale data; actual endpoints are tested via direct HTTP calls
- Python v2 model with `@app.route()` decorators requires `AzureWebJobsFeatureFlags=EnableWorkerIndexing`
- Use SQLAlchemy for Azure SQL connections to avoid pandas warnings about raw DBAPI2 connections

| Issue | Cause | Fix |
|-------|-------|-----|
| **Functions don't appear in Azure Portal** | Python v2 model requires feature flag | Add `AzureWebJobsFeatureFlags=EnableWorkerIndexing` to Function App settings |
| **`mssparkutils.credentials.getToken()` returns 500** | Entra app not configured with "Expose an API" | Portal → Entra ID → App registration → Expose an API → Add scope |
| **401 Unauthorized from Function** | Token audience mismatch | Verify `FUNC_APP_CLIENT_ID` matches your Entra app registration client ID |
| **Audience doesn't match error** | Function expects `api://CLIENT_ID` format | Function code now accepts both formats; redeploy if using old version |
| **403 Forbidden (MSI caller)** | Workspace MSI not whitelisted | Add workspace MSI OID to `allowed-msi-oids` secret in Key Vault (JSON array format) |
| **404 Not Found for login.microsoftonline.com** | `ENTRA_TENANT_ID` empty or incorrect | Set `ENTRA_TENANT_ID` in Function App settings to your tenant ID |
| **500 Key Vault Error** | Function MSI lacks Key Vault permission | Grant Function MSI "Key Vault Secrets User" role on Key Vault |
| **SQL login failed for NT AUTHORITY\ANONYMOUS** | SP lacks database permissions | Grant SP database access: `CREATE USER [sp-name] FROM EXTERNAL PROVIDER; ALTER ROLE db_datareader ADD MEMBER [sp-name];` |
| **pandas SQLAlchemy warning with pyodbc** | pandas prefers SQLAlchemy over raw pyodbc | Use SQLAlchemy engine (see Usage section) or suppress warning with `warnings.filterwarnings('ignore')` |
| **ConnectionError to Function URL** | MPE not created/approved | Create MPE in Fabric workspace settings → Approve in Azure Portal if needed |
| **Wrong scope for SQL** | Used management/graph scope instead of database | Use `https://database.windows.net/.default` for Azure SQL connections |
| **ARM API 403** | SP lacks subscription access | Assign SP appropriate RBAC role (Reader, Contributor, etc.) on subscription/resource group |

### Find Fabric Workspace MSI OID

```powershell
# Method 1: Fabric Portal
# Workspace → Settings → License info → Workspace identity (copy Object ID)

# Method 2: Azure CLI (if you know workspace name)
az ad sp list --display-name "<workspace-name>" --query "[].id" -o tsv
```

### Check Function App Logs

```powershell
# Stream logs
func azure functionapp logstream $FUNCTION_APP

# Or use Azure Portal → Function App → Log stream
```

### Validate Token Audience

Decode the Fabric token to verify it has the correct audience:

```python
import jwt
token = mssparkutils.credentials.getToken(f"api://{FUNC_APP_CLIENT_ID}")
decoded = jwt.decode(token, options={"verify_signature": False})
print(f"Audience: {decoded.get('aud')}")  # Should be api://<CLIENT_ID>
```
