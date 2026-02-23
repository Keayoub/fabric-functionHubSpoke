param(
    [string]$FunctionAppName = "fabricmpeapis",
    [string]$ResourceGroupName = "Fabric-Demos",
    [string]$Location = "eastus"
)

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Azure Function Deployment" -ForegroundColor Cyan
Write-Host "Function App: $FunctionAppName" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "[1/5] Verifying Azure CLI login..." -ForegroundColor Cyan

$account = az account show 2>$null | ConvertFrom-Json
if ($null -eq $account) {
    Write-Host "ERROR: Not logged in to Azure. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "OK: Logged in as $($account.user.name)" -ForegroundColor Green

Write-Host ""
Write-Host "[2/5] Checking resource group '$ResourceGroupName'..." -ForegroundColor Cyan

$rg = az group show --resource-group $ResourceGroupName 2>$null | ConvertFrom-Json
if ($null -eq $rg) {
    Write-Host "Creating resource group..." -ForegroundColor Yellow
    az group create --name $ResourceGroupName --location $Location
    Write-Host "OK: Resource group created" -ForegroundColor Green
} else {
    Write-Host "OK: Resource group exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "[3/5] Finding/creating storage account..." -ForegroundColor Cyan

$storageAccountName = "fabric$(Get-Random -Minimum 100000 -Maximum 999999)st"
$existingStorage = az storage account list --resource-group $ResourceGroupName --query "[0]" 2>$null | ConvertFrom-Json

if ($null -ne $existingStorage) {
    $storageAccountName = $existingStorage.name
    Write-Host "OK: Using storage account $storageAccountName" -ForegroundColor Green
} else {
    Write-Host "Creating storage account..." -ForegroundColor Yellow
    az storage account create --name $storageAccountName --resource-group $ResourceGroupName --location $Location --sku Standard_LRS
    Write-Host "OK: Storage account created" -ForegroundColor Green
}

Write-Host ""
Write-Host "[4/5] Creating/updating Function App '$FunctionAppName'..." -ForegroundColor Cyan

$funcApp = az functionapp show --resource-group $ResourceGroupName --name $FunctionAppName 2>$null | ConvertFrom-Json

if ($null -eq $funcApp) {
    Write-Host "Creating Function App..." -ForegroundColor Yellow
    az functionapp create --resource-group $ResourceGroupName --consumption-plan-location $Location --runtime python --runtime-version 4 --functions-version 4 --name $FunctionAppName --storage-account $storageAccountName
    Write-Host "OK: Function App created" -ForegroundColor Green
} else {
    Write-Host "OK: Function App exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "[5/5] Deploying function code..." -ForegroundColor Cyan

try {
    func azure functionapp publish $FunctionAppName --build remote --force
    Write-Host "OK: Code deployed" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Deployment failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===================================================" -ForegroundColor Green
Write-Host "DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green

Write-Host ""
Write-Host "Function App URL: https://$FunctionAppName.azurewebsites.net" -ForegroundColor Cyan
Write-Host "API Endpoint: https://$FunctionAppName.azurewebsites.net/api/GetSPToken" -ForegroundColor Cyan

Write-Host ""
Write-Host "IMPORTANT: Configure these app settings:" -ForegroundColor Yellow
Write-Host "  az functionapp config appsettings set --name $FunctionAppName --resource-group $ResourceGroupName --settings \" -ForegroundColor Yellow
Write-Host "    ENTRA_TENANT_ID=<your-tenant-id> \" -ForegroundColor Yellow
Write-Host "    FUNC_APP_CLIENT_ID=<your-client-id> \" -ForegroundColor Yellow
Write-Host "    KEY_VAULT_URL=<your-keyvault-url> \" -ForegroundColor Yellow
Write-Host "    SP_CLIENT_ID_SECRET_NAME=sp-client-id \" -ForegroundColor Yellow
Write-Host "    SP_CLIENT_SECRET_NAME=sp-client-secret \" -ForegroundColor Yellow
Write-Host "    SP_TENANT_ID_SECRET_NAME=sp-tenant-id \" -ForegroundColor Yellow
Write-Host "    ALLOWED_MSI_OIDS_SECRET_NAME=allowed-msi-oids" -ForegroundColor Yellow

Write-Host ""
Write-Host "For details: https://docs.microsoft.com/en-us/azure/azure-functions" -ForegroundColor Gray
