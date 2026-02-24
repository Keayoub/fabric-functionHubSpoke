param(
    [string]$FunctionAppName = "fabricmpeapis",
    [string]$ResourceGroupName = "Fabric-Demos",
    [string]$Location = "eastus2"
)

$ErrorActionPreference = "Stop"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Azure Function Deployment" -ForegroundColor Cyan
Write-Host "Function App: $FunctionAppName" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# ── [1/6] Verify Azure CLI login ─────────────────────────────────
Write-Host ""
Write-Host "[1/6] Verifying Azure CLI login..." -ForegroundColor Cyan

$account = az account show 2>$null | ConvertFrom-Json
if ($null -eq $account) {
    Write-Host "ERROR: Not logged in to Azure. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "OK: Logged in as $($account.user.name)" -ForegroundColor Green

# ── [2/6] Ensure Resource Group exists ───────────────────────────
Write-Host ""
Write-Host "[2/6] Checking resource group '$ResourceGroupName'..." -ForegroundColor Cyan

$rg = az group show --resource-group $ResourceGroupName 2>$null | ConvertFrom-Json
if ($null -eq $rg) {
    Write-Host "Creating resource group..." -ForegroundColor Yellow
    az group create --name $ResourceGroupName --location $Location | Out-Null
    Write-Host "OK: Resource group created" -ForegroundColor Green
} else {
    Write-Host "OK: Resource group exists" -ForegroundColor Green
}

# ── [3/6] Ensure Function App exists ─────────────────────────────
Write-Host ""
Write-Host "[3/6] Checking Function App '$FunctionAppName'..." -ForegroundColor Cyan

$funcApp = az functionapp show --resource-group $ResourceGroupName --name $FunctionAppName 2>$null | ConvertFrom-Json
if ($null -eq $funcApp) {
    Write-Host "ERROR: Function App '$FunctionAppName' not found." -ForegroundColor Red
    Write-Host "  Create it in the Azure Portal first (Python 3.12, Linux, Flex Consumption or Consumption plan)." -ForegroundColor Yellow
    exit 1
}
Write-Host "OK: Function App exists (state=$($funcApp.state))" -ForegroundColor Green

# ── [4/6] Install Python packages locally ────────────────────────
# NOTE: Remote build (Oryx) is disabled because the Function App network
#       restricts outbound access to oryx-cdn.microsoft.io.
#       Packages are bundled locally into .python_packages/ and deployed as-is.
Write-Host ""
Write-Host "[4/6] Installing Python packages locally (.python_packages/)..." -ForegroundColor Cyan

$pythonExe = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "python"
}

Remove-Item -Recurse -Force .python_packages -ErrorAction SilentlyContinue
& $pythonExe -m pip install -r requirements.txt --target .python_packages\lib\site-packages --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip install failed" -ForegroundColor Red
    exit 1
}
$pkgCount = (Get-ChildItem .python_packages\lib\site-packages).Count
Write-Host "OK: $pkgCount package folders installed" -ForegroundColor Green

# ── [5/6] Temporarily open network access for deployment ─────────
Write-Host ""
Write-Host "[5/6] Opening public network access temporarily for deployment..." -ForegroundColor Cyan

$originalAccess = (az functionapp show --resource-group $ResourceGroupName --name $FunctionAppName --query "publicNetworkAccess" -o tsv 2>$null).Trim()
$needsRestore   = $originalAccess -eq "Disabled"

if ($needsRestore) {
    az functionapp update --resource-group $ResourceGroupName --name $FunctionAppName --set publicNetworkAccess=Enabled -o none 2>$null
    az resource update --resource-group $ResourceGroupName `
        --name "$FunctionAppName/basicPublishingCredentialsPolicies/scm" `
        --resource-type Microsoft.Web/sites/basicPublishingCredentialsPolicies `
        --set properties.allow=true -o none 2>$null
    Write-Host "OK: Public access enabled — waiting 20s for propagation..." -ForegroundColor Yellow
    Start-Sleep 20
} else {
    Write-Host "OK: Public access already enabled" -ForegroundColor Green
}

# ── [6/6] Deploy ──────────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] Deploying function code (--no-build)..." -ForegroundColor Cyan

try {
    func azure functionapp publish $FunctionAppName --no-build --python
    if ($LASTEXITCODE -ne 0) { throw "func publish returned exit code $LASTEXITCODE" }
    Write-Host "OK: Code deployed" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Deployment failed — $_" -ForegroundColor Red
    # Still restore network settings before exit
    if ($needsRestore) {
        Write-Host "Restoring network restrictions..." -ForegroundColor Yellow
        az functionapp update --resource-group $ResourceGroupName --name $FunctionAppName --set publicNetworkAccess=Disabled -o none 2>$null
        az resource update --resource-group $ResourceGroupName `
            --name "$FunctionAppName/basicPublishingCredentialsPolicies/scm" `
            --resource-type Microsoft.Web/sites/basicPublishingCredentialsPolicies `
            --set properties.allow=false -o none 2>$null
    }
    exit 1
} finally {
    if ($needsRestore) {
        Write-Host "Restoring network restrictions..." -ForegroundColor Yellow
        az functionapp update --resource-group $ResourceGroupName --name $FunctionAppName --set publicNetworkAccess=Disabled -o none 2>$null
        az resource update --resource-group $ResourceGroupName `
            --name "$FunctionAppName/basicPublishingCredentialsPolicies/scm" `
            --resource-type Microsoft.Web/sites/basicPublishingCredentialsPolicies `
            --set properties.allow=false -o none 2>$null
        Write-Host "OK: Network restrictions restored" -ForegroundColor Green
    }
}

# ── Summary ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "===================================================" -ForegroundColor Green
Write-Host "DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Endpoints (via MPE):" -ForegroundColor Cyan
Write-Host "  GET  /api/health      — health check" -ForegroundColor Cyan
Write-Host "  POST /api/GetSPToken  — token broker" -ForegroundColor Cyan
Write-Host ""
Write-Host "Required app settings (if not already configured):" -ForegroundColor Yellow
Write-Host "  az functionapp config appsettings set --name $FunctionAppName --resource-group $ResourceGroupName --settings ENTRA_TENANT_ID=<tid> FUNC_APP_CLIENT_ID=<client-id> KEY_VAULT_URL=<kv-url>" -ForegroundColor Yellow
