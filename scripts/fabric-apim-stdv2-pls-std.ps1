<#
.SYNOPSIS
    Provisions end-to-end private connectivity from Microsoft Fabric OAP to APIM Standard v2 using standard PLS.

.DESCRIPTION
    Automates the following Azure infrastructure deployment:

      Fabric OAP -> Managed Private Endpoint (MPE)
        -> Private Link Service (Standard - via Load Balancer)
        -> Internal Load Balancer
        -> Linux VM (iptables DNAT forwarder)
        -> APIM Private Endpoint (inbound)
        -> APIM Standard v2 (VNet Integration outbound)

    This variant uses a standard Private Link Service backed by an internal load balancer,
    which is available in ALL Azure regions (unlike PLS Direct Connect).

    All provisioning steps are rerun-safe: existing resources are detected and
    reused rather than duplicated.

    PREREQUISITES
      - Azure CLI installed and logged in:  az login
      - Fabric workspace with OAP enabled
      - Contributor permissions on the target subscription

.PARAMETER ValidateOnly
    Runs only the prerequisite checks (Azure CLI login, Fabric workspace API access,
    and config placeholder detection) and exits without creating any Azure or Fabric
    resources. Use this before the first full run.

.PARAMETER FabricWorkspaceId
    GUID of the Fabric workspace that will host the Managed Private Endpoint.
    Find it in the browser URL: https://app.fabric.microsoft.com/groups/{workspace-id}
    Overrides the $FABRIC_WS_ID value set inside the CONFIGURATION section.

.PARAMETER PublisherEmail
    Email address used when creating the APIM instance (required by Azure).
    Overrides the $PUBLISHER_EMAIL value set inside the CONFIGURATION section.

.PARAMETER PublisherName
    Organisation name used when creating the APIM instance.
    Overrides the $PUBLISHER_NAME value set inside the CONFIGURATION section.

.EXAMPLE
    # Run preflight checks only — no Azure resources are created.
    .\fabric-apim-stdv2-pls-standard.ps1 -ValidateOnly `
        -FabricWorkspaceId "<your-fabric-workspace-id>" `
        -PublisherEmail "<your-email>" `
        -PublisherName "<your-org>"

.EXAMPLE
    # Full deployment. Uses parameters to avoid editing the script directly.
    .\fabric-apim-stdv2-pls-standard.ps1 `
        -FabricWorkspaceId "<your-fabric-workspace-id>" `
        -PublisherEmail "<your-email>" `
        -PublisherName "<your-org>"

.EXAMPLE
    # Full deployment when all values are already set in the CONFIGURATION section.
    .\fabric-apim-stdv2-pls-standard.ps1

.NOTES
    To view this help:
        Get-Help .\fabric-apim-stdv2-pls-standard.ps1
        Get-Help .\fabric-apim-stdv2-pls-standard.ps1 -Full
        Get-Help .\fabric-apim-stdv2-pls-standard.ps1 -Examples
#>

param(
    [switch]$ValidateOnly,
    [string]$FabricWorkspaceId,
    [string]$PublisherEmail,
    [string]$PublisherName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

#region --- CONFIGURATION ---

$RG                  = "rg-apim-cc"
$LOCATION            = "canadacentral"     # Works in all regions

# APIM Standard v2
$APIM_NAME           = "apim-stdv2-cc"    # Must be globally unique
$PUBLISHER_EMAIL     = "you@yourdomain.com"
$PUBLISHER_NAME      = "Your Organisation"

# Networking
$VNET_NAME           = "vnet-apim"
$VNET_PREFIX         = "10.10.0.0/16"

# Subnets
$PLS_SUBNET          = "snet-pls"
$PLS_SUBNET_PREFIX   = "10.10.1.0/24"   # PLS + Load Balancer subnet

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
$VM_SIZE             = "Standard_B2s"
$VM_ADMIN            = "azureuser"
$VM_IMAGE            = "Ubuntu2204"

# Internal Load Balancer (for standard PLS)
$LB_NAME             = "lb-apim-internal"
$LB_FRONTEND_NAME    = "lb-frontend"
$LB_BACKEND_NAME     = "lb-backend"
$LB_PROBE_NAME       = "lb-probe-https"
$LB_RULE_NAME        = "lb-rule-https"

# Private Link Service (Standard)
$PLS_NAME            = "pls-apim-standard"

# APIM Private Endpoint (inbound)
$PE_NAME             = "pe-apim-inbound"
$PE_DNS_ZONE         = "privatelink.azure-api.net"

# Fabric — get workspace ID from browser URL:
# https://app.fabric.microsoft.com/groups/{workspace-id}/...
$FABRIC_WS_ID        = "<your-fabric-workspace-id>"
$MPE_NAME            = "mpe-apim-stdv2"

#endregion

# Allow passing key values as parameters instead of editing the script.
if ($PSBoundParameters.ContainsKey("FabricWorkspaceId")) { $FABRIC_WS_ID = $FabricWorkspaceId }
if ($PSBoundParameters.ContainsKey("PublisherEmail")) { $PUBLISHER_EMAIL = $PublisherEmail }
if ($PSBoundParameters.ContainsKey("PublisherName")) { $PUBLISHER_NAME = $PublisherName }

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

function WaitProvisioning($label, $scriptBlock, $interval = 60, $maxAttempts = 60) {
    Log "Waiting for: $label ..."
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $state = (& $scriptBlock | Select-Object -First 1)
        Write-Host "  $(Get-Date -Format 'HH:mm:ss')  $state"
        if ($state -eq "Succeeded") { LogOk "$label provisioned."; break }
        if ($state -eq "Failed")    { LogError "$label failed." }
        if (-not $state)              { LogWarn "$label state not available yet (attempt $attempt of $maxAttempts)." }
        if ($attempt -eq $maxAttempts) { LogError "$label did not reach Succeeded within the allotted time." }
        Start-Sleep -Seconds $interval
    }
}

function WriteJson($path, $content) {
    $content | Set-Content -FilePath $path -Encoding utf8NoBOM
}

function TryGetValue($scriptBlock) {
    try {
        $result = & $scriptBlock 2>$null
        return ($result | Select-Object -First 1)
    }
    catch {
        return $null
    }
}

function GetFabricToken() {
    $token = az account get-access-token --resource https://api.fabric.microsoft.com --query "accessToken" -o tsv
    if (-not $token) {
        LogError "Unable to acquire a Fabric access token from Azure CLI."
    }

    return $token
}

function GetFabricManagedPrivateEndpointByName($workspaceId, $mpeName, $fabricToken) {
    $response = Invoke-RestMethod `
        -Method GET `
        -Uri "https://api.fabric.microsoft.com/v1/workspaces/$workspaceId/managedPrivateEndpoints" `
        -Headers @{ "Authorization" = "Bearer $fabricToken" }

    $items = if ($response.value) {
        $response.value
    }
    elseif ($response.managedPrivateEndpoints) {
        $response.managedPrivateEndpoints
    }
    elseif ($response -is [System.Array]) {
        $response
    }
    else {
        @()
    }

    return @($items | Where-Object { $_.name -eq $mpeName })[0]
}

function GetFabricManagedPrivateEndpointById($workspaceId, $mpeId, $fabricToken) {
    return Invoke-RestMethod `
        -Method GET `
        -Uri "https://api.fabric.microsoft.com/v1/workspaces/$workspaceId/managedPrivateEndpoints/$mpeId" `
        -Headers @{ "Authorization" = "Bearer $fabricToken" }
}

function AssertPrerequisites() {
    Get-Command az -ErrorAction Stop | Out-Null

    if ($FABRIC_WS_ID -match "^<.*>$") {
        LogError "Set FABRIC_WS_ID in the configuration section before running the script."
    }

    if ($PUBLISHER_EMAIL -match "yourdomain\.com" -or $PUBLISHER_NAME -eq "Your Organisation") {
        LogError "Set publisher details in the configuration section before running the script."
    }

    if (-not ($FABRIC_WS_ID -match "^[0-9a-fA-F-]{36}$")) {
        LogError "FABRIC_WS_ID must be a Fabric workspace GUID."
    }

    $accountId = az account show --query "id" -o tsv
    if (-not $accountId) {
        LogError "Azure CLI is not logged in. Run 'az login' and select the correct subscription first."
    }

    $fabricToken = GetFabricToken
    try {
        Invoke-RestMethod `
            -Method GET `
            -Uri "https://api.fabric.microsoft.com/v1/workspaces/$FABRIC_WS_ID/managedPrivateEndpoints" `
            -Headers @{ "Authorization" = "Bearer $fabricToken" } | Out-Null
    }
    catch {
        LogError "Unable to access the Fabric managed private endpoints API for workspace $FABRIC_WS_ID. $($_.Exception.Message)"
    }
}

#endregion

trap {
    $message = if ($_.Exception) { $_.Exception.Message } else { $_.ToString() }
    LogError $message
}

AssertPrerequisites

if ($ValidateOnly) {
    LogOk "Validation completed. Configuration, Azure access, and Fabric workspace access checks passed."
    return
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Fabric OAP -> Standard PLS -> LB -> VM -> APIM Standard v2" -ForegroundColor Cyan
Write-Host "  Pattern: MPE -> PLS (Standard) -> ILB -> VM -> PE -> APIM v2" -ForegroundColor Cyan
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

# snet-pls — PLS and Load Balancer subnet, must disable PLS network policies
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

# snet-vm — Linux forwarder VM (Load Balancer backend)
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
    @{ name = "AllowHTTPS-FromPLS"; priority = 100; src = $PLS_SUBNET_PREFIX; port = "443"; desc = "Allow HTTPS from PLS/LB range" },
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

$APIM_ID = TryGetValue {
    az apim show --resource-group $RG --name $APIM_NAME --query "id" -o tsv
}

if (-not $APIM_ID) {
    az apim create `
        --resource-group $RG `
        --name $APIM_NAME `
        --location $LOCATION `
        --publisher-email $PUBLISHER_EMAIL `
        --publisher-name "$PUBLISHER_NAME" `
        --sku-name StandardV2 `
        --sku-capacity 1 `
        --no-wait | Out-Null
}
else {
    LogWarn "APIM $APIM_NAME already exists. Reusing existing instance."
}

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

$PE_NIC_ID = TryGetValue {
    az network private-endpoint show `
        --resource-group $RG `
        --name $PE_NAME `
        --query "networkInterfaces[0].id" -o tsv
}

if (-not $PE_NIC_ID) {
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
}
else {
    LogWarn "Private Endpoint $PE_NAME already exists. Reusing existing endpoint."
}

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

# Private DNS zone so VNet can resolve apim-stdv2-cc.azure-api.net -> PE IP
if (-not (TryGetValue { az network private-dns zone show --resource-group $RG --name $PE_DNS_ZONE --query "name" -o tsv })) {
    az network private-dns zone create `
        --resource-group $RG `
        --name $PE_DNS_ZONE | Out-Null
}
else {
    LogWarn "Private DNS zone $PE_DNS_ZONE already exists. Reusing existing zone."
}

if (-not (TryGetValue { az network private-dns link vnet show --resource-group $RG --zone-name $PE_DNS_ZONE --name "dns-link-apim" --query "name" -o tsv })) {
    az network private-dns link vnet create `
        --resource-group $RG `
        --zone-name $PE_DNS_ZONE `
        --name "dns-link-apim" `
        --virtual-network $VNET_NAME `
        --registration-enabled false | Out-Null
}
else {
    LogWarn "Private DNS VNet link dns-link-apim already exists. Reusing existing link."
}

if (-not (TryGetValue { az network private-endpoint dns-zone-group show --resource-group $RG --endpoint-name $PE_NAME --name "apim-dns-group" --query "name" -o tsv })) {
    az network private-endpoint dns-zone-group create `
        --resource-group $RG `
        --endpoint-name $PE_NAME `
        --name "apim-dns-group" `
        --private-dns-zone $PE_DNS_ZONE `
        --zone-name "apim" | Out-Null
}
else {
    LogWarn "Private Endpoint DNS zone group apim-dns-group already exists. Reusing existing mapping."
}
LogOk "Private DNS zone $PE_DNS_ZONE linked"

# =============================================================================
Log "=== STEP 7: Linux VM (IP forwarder — Load Balancer backend) ==="
# =============================================================================

Log "Deploying Linux VM $VM_NAME (~3 min) ..."

if (-not (TryGetValue { az vm show --resource-group $RG --name $VM_NAME --query "id" -o tsv })) {
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
        --public-ip-address "" `
        --nsg "" | Out-Null
    LogOk "VM created: $VM_NAME"
}
else {
    LogWarn "VM $VM_NAME already exists. Reusing existing VM."
}

# Enable IP forwarding on Azure NIC (required for DNAT to work)
$VM_NIC_ID = az vm show `
    --resource-group $RG `
    --name $VM_NAME `
    --query "networkProfile.networkInterfaces[0].id" -o tsv

az network nic update `
    --ids $VM_NIC_ID `
    --ip-forwarding true | Out-Null
LogOk "IP forwarding enabled on VM NIC"

# Get VM private IP
$VM_PRIVATE_IP = az vm show `
    --resource-group $RG `
    --name $VM_NAME `
    --show-details `
    --query "privateIps" -o tsv
LogOk "VM private IP (Load Balancer backend): $VM_PRIVATE_IP"

# Configure iptables DNAT on the Linux VM via run-command
# All HTTPS traffic arriving at VM port 443 is forwarded to APIM PE IP
Log "Configuring iptables DNAT: VM:443 -> APIM PE $APIM_PE_IP:443 ..."

$iptablesScript = @"
#!/bin/bash
set -e

# Enable IP forwarding at kernel level
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf
sysctl -p

# DNAT: redirect HTTPS inbound to APIM Private Endpoint IP
iptables -t nat -C PREROUTING -p tcp --dport 443 -j DNAT --to-destination $($APIM_PE_IP):443 2>/dev/null || \
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $($APIM_PE_IP):443
iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -j MASQUERADE

# Persist rules across reboots
if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
fi
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
    --scripts "@$iptablesFile" `
    --query "value[0].message" -o tsv

Write-Host "  VM script output:" -ForegroundColor Gray
Write-Host $runResult -ForegroundColor Gray
LogOk "iptables DNAT configured on VM"

# =============================================================================
Log "=== STEP 8: Internal Load Balancer for Standard PLS ==="
# =============================================================================

$PLS_SUBNET_ID = az network vnet subnet show `
    --resource-group $RG --vnet-name $VNET_NAME --name $PLS_SUBNET --query "id" -o tsv

# Create internal load balancer
if (-not (TryGetValue { az network lb show --resource-group $RG --name $LB_NAME --query "id" -o tsv })) {
    az network lb create `
        --resource-group $RG `
        --name $LB_NAME `
        --location $LOCATION `
        --sku Standard `
        --vnet-name $VNET_NAME `
        --subnet $PLS_SUBNET `
        --frontend-ip-name $LB_FRONTEND_NAME `
        --backend-pool-name $LB_BACKEND_NAME | Out-Null
    LogOk "Internal Load Balancer created: $LB_NAME"
} else {
    LogWarn "Load Balancer $LB_NAME already exists. Reusing existing LB."
}

# Get VM NIC name for backend pool assignment
$VM_NIC_NAME = Split-Path $VM_NIC_ID -Leaf

# Add VM NIC to backend pool
$backendExists = TryGetValue {
    az network nic ip-config show `
        --resource-group $RG `
        --nic-name $VM_NIC_NAME `
        --name "ipconfig1" `
        --query "loadBalancerBackendAddressPools[?contains(id, '$LB_BACKEND_NAME')].id" -o tsv
}

if (-not $backendExists) {
    az network nic ip-config address-pool add `
        --resource-group $RG `
        --nic-name $VM_NIC_NAME `
        --ip-config-name "ipconfig1" `
        --lb-name $LB_NAME `
        --address-pool $LB_BACKEND_NAME | Out-Null
    LogOk "VM added to load balancer backend pool"
} else {
    LogWarn "VM already in load balancer backend pool"
}

# Create health probe
if (-not (TryGetValue { az network lb probe show --resource-group $RG --lb-name $LB_NAME --name $LB_PROBE_NAME --query "id" -o tsv })) {
    az network lb probe create `
        --resource-group $RG `
        --lb-name $LB_NAME `
        --name $LB_PROBE_NAME `
        --protocol Tcp `
        --port 443 `
        --interval 15 `
        --threshold 2 | Out-Null
    LogOk "Health probe created: $LB_PROBE_NAME"
} else {
    LogWarn "Health probe $LB_PROBE_NAME already exists."
}

# Create load balancing rule
if (-not (TryGetValue { az network lb rule show --resource-group $RG --lb-name $LB_NAME --name $LB_RULE_NAME --query "id" -o tsv })) {
    az network lb rule create `
        --resource-group $RG `
        --lb-name $LB_NAME `
        --name $LB_RULE_NAME `
        --protocol Tcp `
        --frontend-port 443 `
        --backend-port 443 `
        --frontend-ip-name $LB_FRONTEND_NAME `
        --backend-pool-name $LB_BACKEND_NAME `
        --probe-name $LB_PROBE_NAME | Out-Null
    LogOk "Load balancing rule created: $LB_RULE_NAME"
} else {
    LogWarn "Load balancing rule $LB_RULE_NAME already exists."
}

$LB_FRONTEND_IP = az network lb frontend-ip show `
    --resource-group $RG `
    --lb-name $LB_NAME `
    --name $LB_FRONTEND_NAME `
    --query "privateIPAddress" -o tsv
LogOk "Load Balancer frontend IP: $LB_FRONTEND_IP"

# =============================================================================
Log "=== STEP 9: Private Link Service (Standard) -> Load Balancer ==="
# =============================================================================

$LB_FRONTEND_ID = az network lb frontend-ip show `
    --resource-group $RG `
    --lb-name $LB_NAME `
    --name $LB_FRONTEND_NAME `
    --query "id" -o tsv

if (-not (TryGetValue { az network private-link-service show --resource-group $RG --name $PLS_NAME --query "id" -o tsv })) {
    az network private-link-service create `
        --resource-group $RG `
        --name $PLS_NAME `
        --location $LOCATION `
        --vnet-name $VNET_NAME `
        --subnet $PLS_SUBNET `
        --lb-frontend-ip-configs $LB_FRONTEND_ID | Out-Null
    
    WaitProvisioning "PLS Standard" {
        az network private-link-service show `
            --resource-group $RG --name $PLS_NAME --query "provisioningState" -o tsv 2>$null
    } -interval 30
    
    LogOk "Standard PLS created: $PLS_NAME"
} else {
    LogWarn "Private Link Service $PLS_NAME already exists. Reusing existing PLS."
}

$PLS_ID = az network private-link-service show `
    --resource-group $RG --name $PLS_NAME --query "id" -o tsv
LogOk "PLS ID: $PLS_ID"
LogOk "PLS frontend: Load Balancer ($LB_FRONTEND_IP) -> VM $VM_PRIVATE_IP"

# =============================================================================
Log "=== STEP 10: Fabric Managed Private Endpoint ==="
# =============================================================================

$FABRIC_TOKEN = GetFabricToken

$existingMpe = GetFabricManagedPrivateEndpointByName $FABRIC_WS_ID $MPE_NAME $FABRIC_TOKEN

if ($existingMpe) {
    $MPE_ID = $existingMpe.id
    LogWarn "Managed private endpoint $MPE_NAME already exists. Reusing existing endpoint $MPE_ID."
}
else {
    $mpeFile = "$env:TEMP\fabric-mpe.json"
    WriteJson $mpeFile @"
{
  "name": "$MPE_NAME",
  "targetPrivateLinkResourceId": "$PLS_ID",
  "targetFQDNs": ["$APIM_NAME.azure-api.net"],
  "requestMessage": "Fabric OAP to APIM Standard v2 via standard PLS + Load Balancer + VM forwarding"
}
"@

    $mpeResponse = Invoke-RestMethod `
        -Method POST `
        -Uri "https://api.fabric.microsoft.com/v1/workspaces/$FABRIC_WS_ID/managedPrivateEndpoints" `
        -Headers @{ "Authorization" = "Bearer $FABRIC_TOKEN"; "Content-Type" = "application/json" } `
        -Body (Get-Content $mpeFile -Raw)

    $MPE_ID = $mpeResponse.id
    if (-not $MPE_ID) { LogError "Fabric did not return a managed private endpoint id." }
    LogOk "MPE created: $MPE_ID"
    Start-Sleep -Seconds 30
}

# =============================================================================
Log "=== STEP 11: Approve PLS Connection ==="
# =============================================================================

$PENDING_CONN = $null
$retries = 0

while (-not $PENDING_CONN -and $retries -lt 10) {
    $PENDING_CONN = @(az network private-link-service show `
        --resource-group $RG `
        --name $PLS_NAME `
        --query "privateEndpointConnections[?privateLinkServiceConnectionState.status=='Pending'].name" `
        -o tsv)[0]
    if (-not $PENDING_CONN) {
        Write-Host "  No pending connection yet, retrying in 30s ..."
        Start-Sleep -Seconds 30
        $retries++
    }
}

if ($PENDING_CONN) {
    LogOk "Pending connection: $PENDING_CONN"

    az network private-link-service connection update `
        --resource-group $RG `
        --service-name $PLS_NAME `
        --name $PENDING_CONN `
        --connection-status Approved | Out-Null
    LogOk "PLS connection approved."
}
else {
    $FABRIC_TOKEN = GetFabricToken
    $mpe = GetFabricManagedPrivateEndpointById $FABRIC_WS_ID $MPE_ID $FABRIC_TOKEN
    if ($mpe.provisioningState -eq "Succeeded" -or $mpe.connectionState.status -eq "Approved") {
        LogWarn "No pending PLS connection found. The Fabric managed private endpoint appears to be approved already."
    }
    else {
        LogError "No pending PLS connection found after retries."
    }
}

# =============================================================================
Log "=== STEP 12: Wait for MPE Succeeded ==="
# =============================================================================

for ($attempt = 1; $attempt -le 60; $attempt++) {
    $FABRIC_TOKEN = GetFabricToken

    $mpe = GetFabricManagedPrivateEndpointById $FABRIC_WS_ID $MPE_ID $FABRIC_TOKEN

    Write-Host "  $(Get-Date -Format 'HH:mm:ss')  provisioningState: $($mpe.provisioningState)  |  connectionState: $($mpe.connectionState.status)"

    if ($mpe.provisioningState -eq "Succeeded") { break }
    if ($mpe.provisioningState -eq "Failed")    { LogError "MPE provisioning failed." }
    if ($mpe.connectionState.status -eq "Rejected") { LogError "MPE connection was rejected." }
    if ($attempt -eq 60) { LogError "MPE did not reach Succeeded within the allotted time." }

    Start-Sleep -Seconds 60
}

# =============================================================================
Log "=== SETUP COMPLETE ==="
# =============================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Traffic flow:" -ForegroundColor Green
Write-Host "  Fabric OAP -> MPE -> PLS -> ILB ($LB_FRONTEND_IP) -> VM ($VM_PRIVATE_IP)" -ForegroundColor White
Write-Host "  VM (iptables DNAT) -> APIM PE ($APIM_PE_IP)" -ForegroundColor White
Write-Host "  APIM Standard v2 (VNet Integration) -> Backend APIs" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Fabric Workspace  : $FABRIC_WS_ID"                                         -ForegroundColor White
Write-Host "  MPE               : $MPE_NAME ($MPE_ID)"                                    -ForegroundColor White
Write-Host "  PLS               : $PLS_NAME (Standard)"                                   -ForegroundColor White
Write-Host "  Load Balancer     : $LB_NAME ($LB_FRONTEND_IP)"                            -ForegroundColor White
Write-Host "  VM Forwarder      : $VM_NAME ($VM_PRIVATE_IP) -> PE $APIM_PE_IP"          -ForegroundColor White
Write-Host "  APIM              : $APIM_NAME (Standard v2)"                              -ForegroundColor White
Write-Host "  APIM PE IP        : $APIM_PE_IP"                                            -ForegroundColor White
Write-Host "  APIM Endpoint     : https://$APIM_NAME.azure-api.net"                     -ForegroundColor White
Write-Host "  Connection State  : $($mpe.connectionState.status)"                         -ForegroundColor Green
Write-Host ""
LogOk "Call APIM from Fabric notebooks using: https://$APIM_NAME.azure-api.net"
