# =============================================================================
# Fabric OAP -> APIM Private Connectivity Setup
# Pattern: Fabric MPE -> PLS Direct Connect -> Linux VM -> APIM Standard v2
#          (PE inbound + VNet Integration outbound)
#
# PREREQUISITES
#   - Azure CLI installed and logged in: az login
#   - Fabric workspace with OAP enabled
#   - Contributor permissions on the subscription
#   - PLS Direct Connect feature flag registered:
#       az feature register --namespace Microsoft.Network \
#         --name AllowPrivateLinkserviceUDR
#
# BEFORE RUNNING — update the CONFIGURATION section below:
#   1. $RG              — your resource group name
#   2. $LOCATION        — must match your Fabric capacity region
#   3. $APIM_NAME       — globally unique APIM name
#   4. $PUBLISHER_EMAIL — your email
#   5. $PUBLISHER_NAME  — your organisation name
#   6. $FABRIC_WS_ID    — your Fabric workspace ID
#                         (from browser URL: app.fabric.microsoft.com/groups/{workspace-id})
#
# USAGE
#   .\fabric-apim-stdv2-pls.ps1
# =============================================================================

#region --- CONFIGURATION ---

$RG                  = "rg-apim"
$LOCATION            = "eastus2"           # Must match Fabric capacity region

# APIM Standard v2
$APIM_NAME           = "apim-stdv2-poc"   # Must be globally unique
$PUBLISHER_EMAIL     = "you@yourdomain.com"
$PUBLISHER_NAME      = "Your Organisation"

# Networking
$VNET_NAME           = "vnet-apim"
$VNET_PREFIX         = "10.10.0.0/16"

# Subnets
$PLS_SUBNET          = "snet-pls"
$PLS_SUBNET_PREFIX   = "10.10.1.0/24"   # PLS NAT subnet

$VM_SUBNET           = "snet-vm"
$VM_SUBNET_PREFIX    = "10.10.2.0/24"   # Linux forwarder VM

$PE_SUBNET           = "snet-pe"
$PE_SUBNET_PREFIX    = "10.10.3.0/24"   # APIM Private Endpoint NIC

$APIM_INT_SUBNET     = "snet-apim-integration"
$APIM_INT_PREFIX     = "10.10.4.0/24"   # APIM VNet Integration (outbound)

# NSG
$NSG_VM_NAME         = "nsg-vm"

# Linux VM (IP forwarder)
$VM_NAME             = "vm-pls-forwarder"
$VM_SIZE             = "Standard_B2s"   # ~CAD$35/month
$VM_ADMIN            = "azureuser"
$VM_IMAGE            = "Ubuntu2204"

# Private Link Service
$PLS_NAME            = "pls-apim-directconnect"

# APIM Private Endpoint (inbound)
$PE_NAME             = "pe-apim-inbound"
$PE_DNS_ZONE         = "privatelink.azure-api.net"

# Fabric — get workspace ID from browser URL:
#   https://app.fabric.microsoft.com/groups/{workspace-id}/...
$FABRIC_WS_ID        = "<your-fabric-workspace-id>"
$MPE_NAME            = "mpe-apim-stdv2"

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

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Fabric OAP -> PLS -> VM -> APIM Standard v2 POC" -ForegroundColor Cyan
Write-Host "  Pattern: MPE -> PLS Direct Connect -> VM -> PE -> APIM v2" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$SUB_ID = az account show --query "id" -o tsv
Write-Host "  Subscription : $SUB_ID"   -ForegroundColor Gray
Write-Host "  Location     : $LOCATION" -ForegroundColor Gray
Write-Host "  Fabric WS    : $FABRIC_WS_ID" -ForegroundColor Gray
Write-Host ""

# =============================================================================
Log "=== STEP 1: Resource Group ==="
# =============================================================================

az group create --name $RG --location $LOCATION | Out-Null
LogOk "Resource group: $RG"

# =============================================================================
Log "=== STEP 2: VNet + Subnets ==="
# =============================================================================

az network vnet create `
    --resource-group $RG `
    --name $VNET_NAME `
    --location $LOCATION `
    --address-prefix $VNET_PREFIX | Out-Null
LogOk "VNet: $VNET_NAME ($VNET_PREFIX)"

# snet-pls — PLS Direct Connect NAT subnet, must disable PLS network policies
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
LogOk "Subnet: $PLS_SUBNET ($PLS_SUBNET_PREFIX) — PLS policies disabled"

# snet-vm — Linux forwarder VM (PLS destination)
az network vnet subnet create `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $VM_SUBNET `
    --address-prefix $VM_SUBNET_PREFIX | Out-Null
LogOk "Subnet: $VM_SUBNET ($VM_SUBNET_PREFIX)"

# snet-pe — APIM Private Endpoint NIC, must disable PE network policies
az network vnet subnet create `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $PE_SUBNET `
    --address-prefix $PE_SUBNET_PREFIX | Out-Null

az network vnet subnet update `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $PE_SUBNET `
    --disable-private-endpoint-network-policies true | Out-Null
LogOk "Subnet: $PE_SUBNET ($PE_SUBNET_PREFIX) — PE policies disabled"

# snet-apim-integration — APIM Standard v2 VNet Integration outbound
# MUST be delegated to Microsoft.Web/serverFarms for Standard v2
az network vnet subnet create `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $APIM_INT_SUBNET `
    --address-prefix $APIM_INT_PREFIX `
    --delegations "Microsoft.Web/serverFarms" | Out-Null
LogOk "Subnet: $APIM_INT_SUBNET ($APIM_INT_PREFIX) — delegated to Microsoft.Web/serverFarms"

# =============================================================================
Log "=== STEP 3: NSG for VM subnet ==="
# =============================================================================

az network nsg create `
    --resource-group $RG `
    --name $NSG_VM_NAME `
    --location $LOCATION | Out-Null

$vmRules = @(
    @{ name = "AllowHTTPS-FromPLS"; priority = 100; src = $PLS_SUBNET_PREFIX; port = "443"; desc = "Allow HTTPS from PLS NAT range" },
    @{ name = "AllowHTTPS-FromVNet"; priority = 110; src = "VirtualNetwork";  port = "443"; desc = "Allow HTTPS from VNet" },
    @{ name = "AllowSSH-Mgmt";      priority = 200; src = "VirtualNetwork";  port = "22";  desc = "SSH management" }
)

foreach ($r in $vmRules) {
    az network nsg rule create `
        --resource-group $RG `
        --nsg-name $NSG_VM_NAME `
        --name $r.name `
        --priority $r.priority `
        --source-address-prefixes $r.src `
        --destination-address-prefixes $VM_SUBNET_PREFIX `
        --destination-port-ranges $r.port `
        --protocol Tcp `
        --access Allow `
        --direction Inbound | Out-Null
    LogOk "NSG rule: $($r.name)"
}

az network vnet subnet update `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $VM_SUBNET `
    --network-security-group $NSG_VM_NAME | Out-Null
LogOk "NSG $NSG_VM_NAME attached to $VM_SUBNET"

# =============================================================================
Log "=== STEP 4: APIM Standard v2 ==="
# =============================================================================

Log "Deploying APIM Standard v2 (~5-10 min) ..."

az apim create `
    --resource-group $RG `
    --name $APIM_NAME `
    --location $LOCATION `
    --publisher-email $PUBLISHER_EMAIL `
    --publisher-name "$PUBLISHER_NAME" `
    --sku-name StandardV2 `
    --sku-capacity 1 `
    --no-wait | Out-Null

WaitProvisioning "APIM Standard v2" {
    az apim show --resource-group $RG --name $APIM_NAME --query "provisioningState" -o tsv 2>$null
}

$APIM_ID = az apim show `
    --resource-group $RG --name $APIM_NAME --query "id" -o tsv
LogOk "APIM ID: $APIM_ID"

# =============================================================================
Log "=== STEP 5: APIM VNet Integration (outbound) ==="
# =============================================================================

# Standard v2 uses VNet Integration (not injection)
# Subnet must be delegated to Microsoft.Web/serverFarms (done in Step 2)
$APIM_INT_SUBNET_ID = az network vnet subnet show `
    --resource-group $RG `
    --vnet-name $VNET_NAME `
    --name $APIM_INT_SUBNET `
    --query "id" -o tsv

$vnetIntFile = "$env:TEMP\apim-vnet-integration.json"
WriteJson $vnetIntFile @"
{
  "properties": {
    "virtualNetworkType": "External",
    "virtualNetworkConfiguration": {
      "subnetResourceId": "$APIM_INT_SUBNET_ID"
    }
  }
}
"@

az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$($APIM_NAME)?api-version=2024-05-01" `
    --body "@$vnetIntFile" `
    --headers "Content-Type=application/json" | Out-Null

WaitProvisioning "APIM VNet Integration" {
    az apim show --resource-group $RG --name $APIM_NAME --query "provisioningState" -o tsv 2>$null
}
LogOk "APIM outbound VNet Integration on $APIM_INT_SUBNET"

# =============================================================================
Log "=== STEP 6: APIM Private Endpoint (inbound) ==="
# =============================================================================

$APIM_ID = az apim show `
    --resource-group $RG --name $APIM_NAME --query "id" -o tsv

az network private-endpoint create `
    --resource-group $RG `
    --name $PE_NAME `
    --location $LOCATION `
    --vnet-name $VNET_NAME `
    --subnet $PE_SUBNET `
    --private-connection-resource-id $APIM_ID `
    --group-id "Gateway" `
    --connection-name "pe-apim-conn" | Out-Null
LogOk "Private Endpoint created: $PE_NAME"

# Retrieve PE NIC private IP — this is what the VM will DNAT to
$PE_NIC_ID = az network private-endpoint show `
    --resource-group $RG `
    --name $PE_NAME `
    --query "networkInterfaces[0].id" -o tsv

$APIM_PE_IP = az network nic show `
    --ids $PE_NIC_ID `
    --query "ipConfigurations[0].privateIPAddress" -o tsv

if (-not $APIM_PE_IP) { LogError "Could not retrieve APIM PE private IP." }
LogOk "APIM PE private IP: $APIM_PE_IP"

# Private DNS zone so VNet can resolve apim-stdv2-poc.azure-api.net -> PE IP
az network private-dns zone create `
    --resource-group $RG `
    --name $PE_DNS_ZONE | Out-Null

az network private-dns link vnet create `
    --resource-group $RG `
    --zone-name $PE_DNS_ZONE `
    --name "dns-link-apim" `
    --virtual-network $VNET_NAME `
    --registration-enabled false | Out-Null

az network private-endpoint dns-zone-group create `
    --resource-group $RG `
    --endpoint-name $PE_NAME `
    --name "apim-dns-group" `
    --private-dns-zone $PE_DNS_ZONE `
    --zone-name "apim" | Out-Null
LogOk "Private DNS zone $PE_DNS_ZONE linked"

# =============================================================================
Log "=== STEP 7: Linux VM (IP forwarder — PLS destination) ==="
# =============================================================================

Log "Deploying Linux VM $VM_NAME (~3 min) ..."

az vm create `
    --resource-group $RG `
    --name $VM_NAME `
    --location $LOCATION `
    --image $VM_IMAGE `
    --size $VM_SIZE `
    --admin-username $VM_ADMIN `
    --generate-ssh-keys `
    --vnet-name $VNET_NAME `
    --subnet $VM_SUBNET `
    --public-ip-address '""' `
    --nsg '""' | Out-Null
LogOk "VM created: $VM_NAME"

# Enable IP forwarding on Azure NIC (required for DNAT to work)
$VM_NIC_ID = az vm show `
    --resource-group $RG `
    --name $VM_NAME `
    --query "networkProfile.networkInterfaces[0].id" -o tsv

az network nic update `
    --ids $VM_NIC_ID `
    --ip-forwarding true | Out-Null
LogOk "IP forwarding enabled on VM NIC"

# Get VM private IP — this is the PLS Direct Connect destination
$VM_PRIVATE_IP = az vm show `
    --resource-group $RG `
    --name $VM_NAME `
    --show-details `
    --query "privateIps" -o tsv
LogOk "VM private IP (PLS destination): $VM_PRIVATE_IP"

# Configure iptables DNAT on the Linux VM via run-command
# All HTTPS traffic arriving at VM port 443 is forwarded to APIM PE IP
Log "Configuring iptables DNAT: VM:443 -> APIM PE $APIM_PE_IP:443 ..."

$iptablesScript = @"
#!/bin/bash
set -e

# Enable IP forwarding at kernel level
echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf
sysctl -p

# DNAT: redirect HTTPS inbound to APIM Private Endpoint IP
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $($APIM_PE_IP):443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Persist rules across reboots
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
netfilter-persistent save

echo '--- iptables NAT table ---'
iptables -t nat -L -n -v
echo 'Done'
"@

$iptablesFile = "$env:TEMP\vm-iptables.sh"
WriteJson $iptablesFile $iptablesScript

$runResult = az vm run-command invoke `
    --resource-group $RG `
    --name $VM_NAME `
    --command-id RunShellScript `
    --scripts @$iptablesFile `
    --query "value[0].message" -o tsv

Write-Host "  VM script output:" -ForegroundColor Gray
Write-Host $runResult -ForegroundColor Gray
LogOk "iptables DNAT configured on VM"

# =============================================================================
Log "=== STEP 8: Private Link Service Direct Connect -> VM ==="
# =============================================================================

# PLS targets the VM private IP (NOT the APIM PE IP — that would violate PLS limitation)
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
    "destinationIPAddress": "$VM_PRIVATE_IP",
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
LogOk "PLS destination: VM $VM_PRIVATE_IP (not PE IP — PLS limitation respected)"

# =============================================================================
Log "=== STEP 9: Fabric Managed Private Endpoint ==="
# =============================================================================

$FABRIC_TOKEN = az account get-access-token `
    --resource https://api.fabric.microsoft.com --query "accessToken" -o tsv

$mpeFile = "$env:TEMP\fabric-mpe.json"
WriteJson $mpeFile @"
{
  "name": "$MPE_NAME",
  "targetPrivateLinkResourceId": "$PLS_ID",
  "targetFQDNs": ["$APIM_NAME.azure-api.net"],
  "requestMessage": "Fabric OAP to APIM Standard v2 via PLS Direct Connect + VM forwarding"
}
"@

$mpeResponse = Invoke-RestMethod `
    -Method POST `
    -Uri "https://api.fabric.microsoft.com/v1/workspaces/$FABRIC_WS_ID/managedPrivateEndpoints" `
    -Headers @{ "Authorization" = "Bearer $FABRIC_TOKEN"; "Content-Type" = "application/json" } `
    -Body (Get-Content $mpeFile -Raw)

$MPE_ID = $mpeResponse.id
LogOk "MPE created: $MPE_ID"
Start-Sleep -Seconds 30

# =============================================================================
Log "=== STEP 10: Approve PLS Connection ==="
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
Log "=== STEP 11: Wait for MPE Succeeded ==="
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
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Traffic flow:" -ForegroundColor Green
Write-Host "  Fabric OAP -> MPE -> PLS -> VM ($VM_PRIVATE_IP)" -ForegroundColor White
Write-Host "  VM (iptables DNAT) -> APIM PE ($APIM_PE_IP)" -ForegroundColor White
Write-Host "  APIM Standard v2 (VNet Integration) -> Backend APIs" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Fabric Workspace  : $FABRIC_WS_ID (WS-HUB-OAP)"                   -ForegroundColor White
Write-Host "  MPE               : $MPE_NAME ($MPE_ID)"                            -ForegroundColor White
Write-Host "  PLS               : $PLS_NAME -> VM $VM_PRIVATE_IP"                 -ForegroundColor White
Write-Host "  VM Forwarder      : $VM_NAME ($VM_PRIVATE_IP) -> PE $APIM_PE_IP"    -ForegroundColor White
Write-Host "  APIM              : $APIM_NAME (Standard v2)"                       -ForegroundColor White
Write-Host "  APIM PE IP        : $APIM_PE_IP"                                    -ForegroundColor White
Write-Host "  APIM Endpoint     : https://$APIM_NAME.azure-api.net"               -ForegroundColor White
Write-Host "  Connection State  : $($mpe.connectionState.status)"                 -ForegroundColor Green
Write-Host ""
LogOk "Call APIM from Fabric notebooks using: https://$APIM_NAME.azure-api.net"
