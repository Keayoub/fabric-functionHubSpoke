# Fabric Hub & Spoke - Azure Function App

Centralized Service Principal token broker for Microsoft Fabric workspaces using Hub & Spoke architecture.

## 🏗️ Architecture

```
┌─────────────── HUB ──────────────────┐
│  Azure Function + Key Vault          │
│  - SP credentials in Key Vault       │
│  - Whitelist-based MSI authorization │
└──────────────┬───────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
[Spoke A]            [Spoke B]
Workspace           Workspace
- Notebooks         - Pipelines
- Pipelines         - Spark Jobs
```

## 🎯 Features

✅ **Dual Caller Support**: Works for both interactive users AND automated pipelines  
✅ **Zero Credential Sprawl**: SP credentials stored only in Key Vault  
✅ **Easy Onboarding**: Add workspace MSI OID to whitelist—no redeployment  
✅ **Full Audit Trail**: Logs every request with caller identity  
✅ **Enterprise Security**: JWT validation with JWKS caching + key rotation support  

## 📁 Project Structure

```
fabric-functionHubSpoke/
├── function_app.py          # Main Function App (Python v2 model)
├── host.json                # Function host configuration
├── requirements.txt         # Python dependencies
├── local.settings.json      # Local development settings (gitignored)
├── .funcignore             # Files excluded from deployment
├── .gitignore              # Git exclusions
│
├── keyvault_setup.py       # Script to bootstrap Key Vault secrets
├── fabric_notebook_v2.py   # Client code for Fabric notebooks
├── azure_function_v2.py    # Reference implementation (v1 model)
└── fabric_hub_spoke_v2.html # Architecture documentation
```

## 🚀 Deployment

### Prerequisites

1. **Azure CLI** installed and logged in
2. **Python 3.9+** with Azure Functions Core Tools
3. **Azure Function App** created with:
   - Python 3.11 runtime
   - Managed Identity enabled
   - Application Insights enabled (recommended)

### Step 1: Install Azure Functions Core Tools

```powershell
# Windows (using Chocolatey)
choco install azure-functions-core-tools-4

# Or using npm
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

### Step 2: Create Azure Resources

```powershell
# Variables
$RESOURCE_GROUP = "rg-fabric-hub"
$LOCATION = "eastus"
$FUNCTION_APP = "func-fabric-token-broker"
$STORAGE = "stfabrichub$(Get-Random -Min 1000 -Max 9999)"
$KEY_VAULT = "kv-fabric-hub"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create storage account (required for Functions)
az storage account create `
  --name $STORAGE `
  --resource-group $RESOURCE_GROUP `
  --location $LOCATION `
  --sku Standard_LRS

# Create Key Vault
az keyvault create `
  --name $KEY_VAULT `
  --resource-group $RESOURCE_GROUP `
  --location $LOCATION `
  --enable-rbac-authorization true

# Create Function App with Managed Identity
az functionapp create `
  --name $FUNCTION_APP `
  --resource-group $RESOURCE_GROUP `
  --storage-account $STORAGE `
  --runtime python `
  --runtime-version 3.11 `
  --functions-version 4 `
  --os-type Linux `
  --assign-identity [system]
```

### Step 3: Configure Environment Variables

```powershell
$TENANT_ID = az account show --query tenantId -o tsv
$KV_URL = "https://$KEY_VAULT.vault.azure.net/"

# Set Function App settings
az functionapp config appsettings set `
  --name $FUNCTION_APP `
  --resource-group $RESOURCE_GROUP `
  --settings `
    ENTRA_TENANT_ID=$TENANT_ID `
    FUNC_APP_CLIENT_ID="<your-function-app-registration-client-id>" `
    KEY_VAULT_URL=$KV_URL `
    SP_CLIENT_ID_SECRET_NAME="sp-client-id" `
    SP_CLIENT_SECRET_NAME="sp-client-secret" `
    SP_TENANT_ID_SECRET_NAME="sp-tenant-id" `
    ALLOWED_MSI_OIDS_SECRET_NAME="allowed-msi-oids"
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

az role assignment create `
  --role "Key Vault Secrets User" `
  --assignee $FUNCTION_PRINCIPAL_ID `
  --scope $KV_SCOPE
```

### Step 5: Bootstrap Key Vault Secrets

Edit `keyvault_setup.py` with your values and run:

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install azure-identity azure-keyvault-secrets

# Run setup script
python keyvault_setup.py
```

### Step 6: Deploy Function App

```powershell
# From the fabric-functionHubSpoke directory
func azure functionapp publish $FUNCTION_APP
```

## 🧪 Local Testing

```powershell
# Install dependencies
pip install -r requirements.txt

# Update local.settings.json with your values

# Start local Function runtime
func start
```

Test the endpoint:

```powershell
$TOKEN = "<get-fabric-user-token-for-api://your-function-app-id>"

curl -X POST http://localhost:7071/api/GetSPToken `
  -H "Authorization: Bearer $TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"targetScope": "https://management.azure.com/.default"}'
```

## 📝 Usage in Fabric Notebooks

See [fabric_notebook_v2.py](fabric_notebook_v2.py) for complete example:

```python
from notebookutils import mssparkutils
import requests

FUNC_APP_CLIENT_ID = "your-function-app-client-id"
FUNCTION_URL = "https://func-fabric-token-broker.azurewebsites.net/api/GetSPToken"

# Get token for Function
token = mssparkutils.credentials.getToken(f"api://{FUNC_APP_CLIENT_ID}")

# Call Function
response = requests.post(
    FUNCTION_URL,
    headers={"Authorization": f"Bearer {token}"},
    json={"targetScope": "https://management.azure.com/.default"}
)

sp_token = response.json()["access_token"]
# Use sp_token for downstream calls...
```

## 🔐 Security Considerations

- Function must have Managed Identity enabled
- Key Vault uses RBAC (recommended) or Access Policies
- MSI whitelist stored as JSON array in Key Vault secret `allowed-msi-oids`
- JWT validation with automatic JWKS refresh on key rotation
- All credentials flow through Azure Managed Identity—no secrets in code

## 📊 Monitoring

Enable Application Insights for the Function App to track:
- Request volume and latency
- Caller types (USER vs MSI)
- Authorization failures (401/403)
- Token acquisition errors

Query example:
```kusto
traces
| where message contains "GetSPToken"
| where customDimensions.caller_type in ("USER", "MSI")
| summarize count() by bin(timestamp, 1h), tostring(customDimensions.caller_type)
```

## 🛠️ Troubleshooting

**403 Forbidden (MSI caller)**:
- Add workspace MSI OID to Key Vault secret `allowed-msi-oids`
- Find OID: Fabric Workspace → Settings → License info → Workspace identity

**401 Unauthorized**:
- Verify `FUNC_APP_CLIENT_ID` matches App Registration
- Check Function audience in token: `api://<client-id>`

**500 Key Vault Error**:
- Verify Function MSI has "Key Vault Secrets User" role
- Check Key Vault URL in settings

## 📚 References

- [Azure Functions Python Developer Guide](https://learn.microsoft.com/azure/azure-functions/functions-reference-python)
- [Microsoft Fabric Managed Identity](https://learn.microsoft.com/fabric/security/workspace-identity)
- [Azure Key Vault RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)

## 📄 License

See repository root LICENSE file.
