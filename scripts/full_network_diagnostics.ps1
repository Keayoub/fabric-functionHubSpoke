#!/usr/bin/env pwsh
<#!
.SYNOPSIS
    Full diagnostics for Fabric MPE -> Azure Private Link Service -> APIM path.

.DESCRIPTION
    Runs end-to-end checks to help troubleshoot connect timeout issues when
    Fabric workspaces call private APIs through Managed Private Endpoints.

    The script can validate:
    - Azure Private Link Service configuration and connections
    - Load Balancer frontend/rules/probes
    - Fabric Managed Private Endpoint list/status for a workspace
    - DNS, TCP, and HTTPS reachability from the machine running the script
    - Optional VM forwarding checks via az vm run-command invoke

    Output is written to console and to a JSON report file.

.EXAMPLE
    ./scripts/full_network_diagnostics.ps1 \
      -SubscriptionId "00000000-0000-0000-0000-000000000000" \
      -ResourceGroup "azapim-dev-rg" \
      -PrivateLinkServiceName "apim-dev-pls01" \
      -LoadBalancerName "apim-dev-lb" \
      -FabricWorkspaceId "11111111-1111-1111-1111-111111111111" \
      -ManagedPrivateEndpointName "mpe-apim-dev01" \
      -Hostnames "stc-poc-dev-apim.azure-api.net" \
      -TestUrl "https://stc-poc-dev-apim.azure-api.net/health"

.EXAMPLE
    ./scripts/full_network_diagnostics.ps1 \
      -ResourceGroup "azapim-dev-rg" \
      -PrivateLinkServiceName "apim-dev-pls01" \
      -Hostnames "stc-poc-dev-apim.azure-api.net" \
      -VmResourceGroup "azapim-dev-rg" \
      -VmName "fwd-apim-dev-vm"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$PrivateLinkServiceName,

    [Parameter(Mandatory = $false)]
    [string]$LoadBalancerName,

    [Parameter(Mandatory = $false)]
    [string]$FabricWorkspaceId,

    [Parameter(Mandatory = $false)]
    [string]$ManagedPrivateEndpointName,

    [Parameter(Mandatory = $false)]
    [string[]]$Hostnames = @(),

    [Parameter(Mandatory = $false)]
    [string]$TestUrl,

    [Parameter(Mandatory = $false)]
    [string]$FabricToken,

    [Parameter(Mandatory = $false)]
    [string]$VmResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$VmName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",

    [Parameter(Mandatory = $false)]
    [int]$TcpTimeoutMs = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "- $Message" -ForegroundColor Yellow
}

function New-Result {
    param(
        [string]$Name,
        [bool]$Success,
        [object]$Data,
        [string]$ErrorMessage = ""
    )

    [PSCustomObject]@{
        name    = $Name
        success = $Success
        data    = $Data
        error   = $ErrorMessage
    }
}

function Invoke-AzJson {
    param([string[]]$Arguments)

    $raw = & az @Arguments --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az $($Arguments -join ' ') failed: $raw"
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return ($raw | ConvertFrom-Json -Depth 100)
}

function Get-FabricAccessToken {
    param([string]$ExistingToken)

    if (-not [string]::IsNullOrWhiteSpace($ExistingToken)) {
        return $ExistingToken
    }

    try {
        $token = & az account get-access-token --resource "https://api.fabric.microsoft.com" --query accessToken -o tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($token)) {
            return $token.Trim()
        }
    }
    catch {
        return ""
    }

    return ""
}

function Test-TcpPort {
    param(
        [string]$Host,
        [int]$Port,
        [int]$TimeoutMs
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Host, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) {
            return @{ connected = $false; reason = "timeout" }
        }
        $client.EndConnect($iar)
        return @{ connected = $true; reason = "connected" }
    }
    catch {
        return @{ connected = $false; reason = $_.Exception.Message }
    }
    finally {
        $client.Close()
        $client.Dispose()
    }
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $env:TEMP "fabric-apim-network-diagnostics-$stamp.json"
}

$report = [ordered]@{
    timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    parameters   = [ordered]@{
        subscriptionId            = $SubscriptionId
        resourceGroup             = $ResourceGroup
        privateLinkServiceName    = $PrivateLinkServiceName
        loadBalancerName          = $LoadBalancerName
        fabricWorkspaceId         = $FabricWorkspaceId
        managedPrivateEndpointName = $ManagedPrivateEndpointName
        hostnames                 = $Hostnames
        testUrl                   = $TestUrl
        vmResourceGroup           = $VmResourceGroup
        vmName                    = $VmName
        tcpTimeoutMs              = $TcpTimeoutMs
    }
    checks       = @()
    summary      = [ordered]@{
        totalChecks  = 0
        passedChecks = 0
        failedChecks = 0
    }
}

Write-Section "Full Network Diagnostics"
Write-Host "Output report: $OutputPath" -ForegroundColor Gray

try {
    Write-Step "Verifying Azure CLI is available"
    $null = & az version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI (az) is not available."
    }
    $report.checks += New-Result -Name "az_cli_available" -Success $true -Data @{ ok = $true }
}
catch {
    $report.checks += New-Result -Name "az_cli_available" -Success $false -Data $null -ErrorMessage $_.Exception.Message
    $report.summary.totalChecks = $report.checks.Count
    $report.summary.passedChecks = ($report.checks | Where-Object { $_.success }).Count
    $report.summary.failedChecks = ($report.checks | Where-Object { -not $_.success }).Count
    ($report | ConvertTo-Json -Depth 100) | Set-Content -Path $OutputPath -Encoding UTF8
    throw
}

try {
    Write-Step "Getting current Azure account context"
    $account = Invoke-AzJson -Arguments @("account", "show")
    $report.checks += New-Result -Name "az_account_context" -Success $true -Data $account
}
catch {
    $report.checks += New-Result -Name "az_account_context" -Success $false -Data $null -ErrorMessage $_.Exception.Message
}

if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    try {
        Write-Step "Setting Azure subscription context"
        $null = & az account set --subscription $SubscriptionId 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set subscription to $SubscriptionId"
        }
        $report.checks += New-Result -Name "az_set_subscription" -Success $true -Data @{ subscriptionId = $SubscriptionId }
    }
    catch {
        $report.checks += New-Result -Name "az_set_subscription" -Success $false -Data @{ subscriptionId = $SubscriptionId } -ErrorMessage $_.Exception.Message
    }
}

try {
    Write-Section "Private Link Service"
    Write-Step "Reading Private Link Service details"
    $pls = Invoke-AzJson -Arguments @("network", "private-link-service", "show", "-g", $ResourceGroup, "-n", $PrivateLinkServiceName)
    $plsData = [ordered]@{
        id                         = $pls.id
        name                       = $pls.name
        location                   = $pls.location
        alias                      = $pls.alias
        fqdns                      = $pls.fqdns
        privateEndpointConnections = @($pls.privateEndpointConnections | ForEach-Object {
            [ordered]@{
                name   = $_.name
                status = $_.privateLinkServiceConnectionState.status
                desc   = $_.privateLinkServiceConnectionState.description
                peId   = $_.privateEndpoint.id
            }
        })
    }
    $report.checks += New-Result -Name "private_link_service" -Success $true -Data $plsData
}
catch {
    $report.checks += New-Result -Name "private_link_service" -Success $false -Data @{ resourceGroup = $ResourceGroup; name = $PrivateLinkServiceName } -ErrorMessage $_.Exception.Message
}

if (-not [string]::IsNullOrWhiteSpace($LoadBalancerName)) {
    try {
        Write-Section "Load Balancer"
        Write-Step "Reading Load Balancer details"
        $lb = Invoke-AzJson -Arguments @("network", "lb", "show", "-g", $ResourceGroup, "-n", $LoadBalancerName)
        $lbData = [ordered]@{
            id          = $lb.id
            name        = $lb.name
            sku         = $lb.sku.name
            frontends   = @($lb.frontendIpConfigurations | ForEach-Object {
                [ordered]@{
                    name               = $_.name
                    privateIPAddress   = $_.privateIPAddress
                    privateIPAllocationMethod = $_.privateIPAllocationMethod
                    subnetId           = $_.subnet.id
                }
            })
            probes      = @($lb.probes | ForEach-Object {
                [ordered]@{
                    name      = $_.name
                    protocol  = $_.protocol
                    port      = $_.port
                    path      = $_.requestPath
                    interval  = $_.intervalInSeconds
                    threshold = $_.numberOfProbes
                }
            })
            rules       = @($lb.loadBalancingRules | ForEach-Object {
                [ordered]@{
                    name         = $_.name
                    protocol     = $_.protocol
                    frontendPort = $_.frontendPort
                    backendPort  = $_.backendPort
                    probeId      = $_.probe.id
                }
            })
            backendPools = @($lb.backendAddressPools | ForEach-Object {
                [ordered]@{
                    name                 = $_.name
                    backendIpConfigurations = @($_.backendIPConfigurations.id)
                    loadBalancerBackendAddresses = @($_.loadBalancerBackendAddresses | ForEach-Object {
                        [ordered]@{
                            name = $_.name
                            ip   = $_.ipAddress
                        }
                    })
                }
            })
        }
        $report.checks += New-Result -Name "load_balancer" -Success $true -Data $lbData
    }
    catch {
        $report.checks += New-Result -Name "load_balancer" -Success $false -Data @{ resourceGroup = $ResourceGroup; name = $LoadBalancerName } -ErrorMessage $_.Exception.Message
    }
}

if (-not [string]::IsNullOrWhiteSpace($FabricWorkspaceId)) {
    try {
        Write-Section "Fabric Managed Private Endpoints"
        Write-Step "Getting Fabric access token"
        $token = Get-FabricAccessToken -ExistingToken $FabricToken
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "Unable to get Fabric token. Provide -FabricToken or login with az and ensure access to https://api.fabric.microsoft.com"
        }

        Write-Step "Reading Fabric managed private endpoints"
        $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
        $uri = "https://api.fabric.microsoft.com/v1/workspaces/$FabricWorkspaceId/managedPrivateEndpoints"
        $mpeResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers

        $mpeList = @($mpeResponse.value)
        if (-not [string]::IsNullOrWhiteSpace($ManagedPrivateEndpointName)) {
            $mpeList = @($mpeList | Where-Object { $_.name -eq $ManagedPrivateEndpointName })
        }

        $report.checks += New-Result -Name "fabric_managed_private_endpoints" -Success $true -Data @($mpeList)
    }
    catch {
        $report.checks += New-Result -Name "fabric_managed_private_endpoints" -Success $false -Data @{ workspaceId = $FabricWorkspaceId; mpeName = $ManagedPrivateEndpointName } -ErrorMessage $_.Exception.Message
    }
}

if ($Hostnames.Count -gt 0) {
    Write-Section "DNS/TCP Host Checks"
    foreach ($host in $Hostnames) {
        try {
            Write-Step "Resolving DNS for $host"
            $dnsRecords = @()
            try {
                $dnsRecords = Resolve-DnsName -Name $host -Type A -ErrorAction Stop |
                    Select-Object Name, Type, IPAddress, TTL
            }
            catch {
                $dnsRecords = @([PSCustomObject]@{
                    Name = $host
                    Type = "A"
                    IPAddress = ""
                    TTL = ""
                    Error = $_.Exception.Message
                })
            }

            Write-Step "Testing TCP 443 for $host"
            $tcp = Test-TcpPort -Host $host -Port 443 -TimeoutMs $TcpTimeoutMs

            $hostData = [ordered]@{
                host      = $host
                dnsA      = $dnsRecords
                tcp443    = $tcp
            }

            $report.checks += New-Result -Name "host_check_$host" -Success $true -Data $hostData
        }
        catch {
            $report.checks += New-Result -Name "host_check_$host" -Success $false -Data @{ host = $host } -ErrorMessage $_.Exception.Message
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($TestUrl)) {
    try {
        Write-Section "HTTPS URL Check"
        Write-Step "Calling $TestUrl"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri $TestUrl -Method GET -TimeoutSec 30 -UseBasicParsing
        $sw.Stop()

        $testData = [ordered]@{
            url           = $TestUrl
            statusCode    = [int]$response.StatusCode
            statusMessage = $response.StatusDescription
            elapsedMs     = $sw.ElapsedMilliseconds
            headers       = $response.Headers
        }
        $report.checks += New-Result -Name "https_url_check" -Success $true -Data $testData
    }
    catch {
        $report.checks += New-Result -Name "https_url_check" -Success $false -Data @{ url = $TestUrl } -ErrorMessage $_.Exception.Message
    }
}

if (-not [string]::IsNullOrWhiteSpace($VmResourceGroup) -and -not [string]::IsNullOrWhiteSpace($VmName)) {
    try {
        Write-Section "Forwarding VM Checks"
        Write-Step "Running diagnostic commands on VM via run-command"

        $vmScript = @'
set -e
echo "=== uname ==="
uname -a || true

echo "=== iptables nat ==="
sudo iptables -t nat -L -n -v || true

echo "=== ip_forward ==="
sysctl net.ipv4.ip_forward || true

echo "=== rp_filter ==="
sysctl net.ipv4.conf.all.rp_filter || true

echo "=== routes ==="
ip route || true
'@

        $vmResult = Invoke-AzJson -Arguments @(
            "vm", "run-command", "invoke",
            "-g", $VmResourceGroup,
            "-n", $VmName,
            "--command-id", "RunShellScript",
            "--scripts", $vmScript
        )

        $report.checks += New-Result -Name "vm_forwarding_checks" -Success $true -Data $vmResult
    }
    catch {
        $report.checks += New-Result -Name "vm_forwarding_checks" -Success $false -Data @{ resourceGroup = $VmResourceGroup; vmName = $VmName } -ErrorMessage $_.Exception.Message
    }
}

$report.summary.totalChecks = $report.checks.Count
$report.summary.passedChecks = ($report.checks | Where-Object { $_.success }).Count
$report.summary.failedChecks = ($report.checks | Where-Object { -not $_.success }).Count

($report | ConvertTo-Json -Depth 100) | Set-Content -Path $OutputPath -Encoding UTF8

Write-Section "Summary"
Write-Host "Checks total : $($report.summary.totalChecks)" -ForegroundColor Gray
Write-Host "Checks passed: $($report.summary.passedChecks)" -ForegroundColor Green
if ($report.summary.failedChecks -gt 0) {
    Write-Host "Checks failed: $($report.summary.failedChecks)" -ForegroundColor Red
}
else {
    Write-Host "Checks failed: $($report.summary.failedChecks)" -ForegroundColor Green
}
Write-Host "Report file  : $OutputPath" -ForegroundColor Gray

if ($report.summary.failedChecks -gt 0) {
    Write-Host "`nFailed checks:" -ForegroundColor Yellow
    $report.checks |
        Where-Object { -not $_.success } |
        ForEach-Object {
            Write-Host "- $($_.name): $($_.error)" -ForegroundColor Yellow
        }
}
