# =============================================================================
# Fabric OAP -> APIM Private Connectivity Setup
# Pattern: Fabric MPE -> PLS Direct Connect -> APIM (Internal VNet)
# Region:  East US 2
# =============================================================================

#region --- CONFIGURATION ---

$RG                  = "rg-apim"
$LOCATION            = "eastus2"

# APIM
$APIM_NAME           = "apim-dev01"
$PUBLISHER_EMAIL     = "ayoub@yourdomain.com"
$PUBLISHER_NAME      = "Ayoub"

# Networking
$VNET_NAME           = "vnet-apim"
$VNET_PREFIX         = "10.10.0.0/16"
$APIM_SUBNET         = "snet-apim"
$APIM_SUBNET_PREFIX  = "10.10.1.0/24"
$PLS_SUBNET          = "snet-pls"
$PLS_SUBNET_PREFIX   = "10.10.2.0/24"
$NSG_NAME            = "nsg-apim"
$PIP_NAME            = "pip-apim"
$PLS_NAME            = "pls-apim-directconnect"

# Fabric
$FABRIC_WS_ID        = "fb53fbfb-d8e9-4797-b2f5-ba80bb9a7388"   # WS-HUB-OAP
$MPE_NAME            = "mpe-apim"

#endregion

#region --- HELPERS ---

function Log($msg) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss')  $msg" -ForegroundColor Cyan
}

function LogOk($msg) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss')  OK  $msg" -ForegroundColor Green
}

function LogWarn($msg) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss')  WARN  $msg" -ForegroundColor Yellow
}

function LogError($msg) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss')  ERROR  $msg" -ForegroundColor Red
    exit 1
}

function WaitProvisioning($label, $scriptBlock, $interval = 60) {
    Log "Waiting for: $label ..."
    while ($true) {
        $state = & $scriptBlock
        Write-Host "  $(Get-Date -Format 'HH:mm:ss')  $state"
        if ($state -eq "Succeeded") { LogOk "$label provisioned."; break }
        if ($state -eq "Failed")    { LogError "$label failed." }
        Start-Sleep -Seconds $interval
    }
}

function WriteJson($path, $content) {
    $content | Out-File -FilePath $path -Encoding utf8
}

#endregion

# =============================================================================
Log "=== STEP 1: Resource Group ==="
# =============================================================================

az group create --name $RG --location $LOCATION | Out-Null
LogOk "Resource group: $RG"

# =============================================================================
Log "=== STEP 2: NSG ==="
# =============================================================================

az network nsg create --resource-group $RG --name $NSG_NAME --location $LOCATION | Out-Null

$rules = @(
    @{ name = "AllowAPIMManagement"; priority = 100; src = "ApiManagement";     port = "3443" },
    @{ name = "AllowAzureLB";        priority = 110; src = "AzureLoadBalancer"; port = "6390" },
    @{ name = "AllowHTTPS-VNet";     priority = 200; src = "VirtualNetwork";    port = "443"  }
)

foreach ($r in $rules) {
    az network nsg rule create `
        --resource-group $RG `
        --nsg-name $NSG_NAME `
        --name $r.name `
        --priority $r.priority `
        --source-address-prefixes $r.src `
        --destination-address-prefixes VirtualNetwork `
        --destination-port-ranges $r.port `
        --protocol Tcp `
        --access Allow `
        --direction Inbound | Out-Null
    LogOk "NSG rule: $($r.name)"
}

# =============================================================================
Log "=== STEP 3: VNet + Subnets ==="
# =============================================================================

az network vnet create `
    --resource-group $RG `
    --name $VNET_NAME `
    --location $LOCATION `
    --address-prefix $VNET_PREFIX | Out-Null
LogOk "VNet: $VNET_NAME"

az network vnet subnet create `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $APIM_SUBNET `
    --address-prefix $APIM_SUBNET_PREFIX `
    --network-security-group $NSG_NAME | Out-Null
LogOk "Subnet: $APIM_SUBNET"

az network vnet subnet create `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $PLS_SUBNET `
    --address-prefix $PLS_SUBNET_PREFIX | Out-Null

az network vnet subnet update `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $PLS_SUBNET `
    --disable-private-link-service-network-policies true | Out-Null
LogOk "Subnet: $PLS_SUBNET (PLS network policies disabled)"

# =============================================================================
Log "=== STEP 4: Public IP ==="
# =============================================================================

az network public-ip create `
    --resource-group $RG `
    --name $PIP_NAME `
    --location $LOCATION `
    --sku Standard `
    --allocation-method Static | Out-Null
LogOk "Public IP: $PIP_NAME"

# =============================================================================
Log "=== STEP 5: Deploy APIM (Developer, Internal VNet) ==="
# =============================================================================

az apim create `
    --resource-group $RG `
    --name $APIM_NAME `
    --location $LOCATION `
    --publisher-email $PUBLISHER_EMAIL `
    --publisher-name $PUBLISHER_NAME `
    --sku-name Developer `
    --sku-capacity 1 `
    --no-wait | Out-Null

WaitProvisioning "APIM initial deployment" {
    az apim show --resource-group $RG --name $APIM_NAME --query "provisioningState" -o tsv 2>$null
}

# Inject into VNet
Log "Injecting APIM into VNet (Internal mode) ..."
$SUB_ID         = az account show --query "id" -o tsv
$APIM_SUBNET_ID = az network vnet subnet show `
    --resource-group $RG --vnet-name $VNET_NAME --name $APIM_SUBNET --query "id" -o tsv

$vnetPatchFile = "$env:TEMP\apim-vnet-patch.json"
WriteJson $vnetPatchFile @"
{
  "properties": {
    "virtualNetworkType": "Internal",
    "virtualNetworkConfiguration": {
      "subnetResourceId": "$APIM_SUBNET_ID"
    }
  }
}
"@

az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$($APIM_NAME)?api-version=2023-05-01-preview" `
    --body "@$vnetPatchFile" `
    --headers "Content-Type=application/json" | Out-Null

WaitProvisioning "APIM VNet injection" {
    az apim show --resource-group $RG --name $APIM_NAME --query "provisioningState" -o tsv 2>$null
}

$APIM_PRIVATE_IP = az apim show `
    --resource-group $RG --name $APIM_NAME --query "privateIpAddresses[0]" -o tsv

if (-not $APIM_PRIVATE_IP) { LogError "Could not retrieve APIM private IP." }
LogOk "APIM Private IP: $APIM_PRIVATE_IP"

# =============================================================================
Log "=== STEP 6: Private Link Service (Direct Connect) ==="
# =============================================================================

$PLS_SUBNET_ID = az network vnet subnet show `
    --resource-group $RG --vnet-name $VNET_NAME --name $PLS_SUBNET --query "id" -o tsv

$plsFile = "$env:TEMP\pls-create.json"
WriteJson $plsFile @"
{
  "location": "$LOCATION",
  "properties": {
    "ipConfigurations": [
      {
        "name": "ipconfig1",
        "properties": {
          "privateIPAllocationMethod": "Dynamic",
          "subnet": { "id": "$PLS_SUBNET_ID" },
          "primary": true
        }
      },
      {
        "name": "ipconfig2",
        "properties": {
          "privateIPAllocationMethod": "Dynamic",
          "subnet": { "id": "$PLS_SUBNET_ID" },
          "primary": false
        }
      }
    ],
    "destinationIPAddress": "$APIM_PRIVATE_IP",
    "autoApproval": { "subscriptions": [] },
    "visibility": { "subscriptions": [] }
  }
}
"@

az rest `
    --method PUT `
    --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Network/privateLinkServices/$($PLS_NAME)?api-version=2023-05-01" `
    --body "@$plsFile" `
    --headers "Content-Type=application/json" | Out-Null

WaitProvisioning "PLS Direct Connect" {
    az network private-link-service show `
        --resource-group $RG --name $PLS_NAME --query "provisioningState" -o tsv 2>$null
} -interval 30

$PLS_ID = az network private-link-service show `
    --resource-group $RG --name $PLS_NAME --query "id" -o tsv
LogOk "PLS ID: $PLS_ID"

# =============================================================================
Log "=== STEP 7: Fabric Managed Private Endpoint ==="
# =============================================================================

$FABRIC_TOKEN = az account get-access-token `
    --resource https://api.fabric.microsoft.com --query "accessToken" -o tsv

$mpeFile = "$env:TEMP\fabric-mpe.json"
WriteJson $mpeFile @"
{
  "name": "$MPE_NAME",
  "targetPrivateLinkResourceId": "$PLS_ID",
  "targetFQDNs": ["$APIM_NAME.azure-api.net"],
  "requestMessage": "Fabric OAP workspace to APIM via PLS Direct Connect"
}
"@

$mpeResponse = Invoke-RestMethod `
    -Method POST `
    -Uri "https://api.fabric.microsoft.com/v1/workspaces/$FABRIC_WS_ID/managedPrivateEndpoints" `
    -Headers @{ "Authorization" = "Bearer $FABRIC_TOKEN"; "Content-Type" = "application/json" } `
    -Body (Get-Content $mpeFile -Raw)

$MPE_ID = $mpeResponse.id
LogOk "MPE created: $MPE_ID — waiting for PLS connection to appear ..."
Start-Sleep -Seconds 30

# =============================================================================
Log "=== STEP 8: Approve PLS Connection ==="
# =============================================================================

$PENDING_CONN = $null
$retries = 0

while (-not $PENDING_CONN -and $retries -lt 10) {
    $PENDING_CONN = az network private-link-service show `
        --resource-group $RG `
        --name $PLS_NAME `
        --query "privateEndpointConnections[?privateLinkServiceConnectionState.status=='Pending'].name" `
        -o tsv
    if (-not $PENDING_CONN) {
        Write-Host "  No pending connection yet, retrying in 30s ..."
        Start-Sleep -Seconds 30
        $retries++
    }
}

if (-not $PENDING_CONN) { LogError "No pending PLS connection found after retries." }
LogOk "Pending connection: $PENDING_CONN"

az network private-link-service connection update `
    --resource-group $RG `
    --service-name $PLS_NAME `
    --name $PENDING_CONN `
    --connection-status Approved | Out-Null
LogOk "PLS connection approved."

# =============================================================================
Log "=== STEP 9: Wait for MPE to reach Succeeded ==="
# =============================================================================

while ($true) {
    $FABRIC_TOKEN = az account get-access-token `
        --resource https://api.fabric.microsoft.com --query "accessToken" -o tsv

    $mpe = Invoke-RestMethod `
        -Method GET `
        -Uri "https://api.fabric.microsoft.com/v1/workspaces/$FABRIC_WS_ID/managedPrivateEndpoints/$MPE_ID" `
        -Headers @{ "Authorization" = "Bearer $FABRIC_TOKEN" }

    Write-Host "  $(Get-Date -Format 'HH:mm:ss')  provisioningState: $($mpe.provisioningState)  |  connectionState: $($mpe.connectionState.status)"

    if ($mpe.provisioningState -eq "Succeeded") { break }
    if ($mpe.provisioningState -eq "Failed")    { LogError "MPE provisioning failed." }

    Start-Sleep -Seconds 60
}

# =============================================================================
Log "=== SETUP COMPLETE ==="
# =============================================================================

Write-Host ""
Write-Host "  Fabric Workspace  : $FABRIC_WS_ID (WS-HUB-OAP)"         -ForegroundColor White
Write-Host "  MPE               : $MPE_NAME ($MPE_ID)"                  -ForegroundColor White
Write-Host "  PLS               : $PLS_NAME"                            -ForegroundColor White
Write-Host "  APIM Private IP   : $APIM_PRIVATE_IP"                     -ForegroundColor White
Write-Host "  APIM Endpoint     : https://$APIM_NAME.azure-api.net"     -ForegroundColor White
Write-Host "  Connection State  : $($mpe.connectionState.status)"       -ForegroundColor Green
Write-Host ""
LogOk "Call APIM from Fabric notebooks using: https://$APIM_NAME.azure-api.net"
