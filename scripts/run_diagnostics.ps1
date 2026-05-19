#!/usr/bin/env pwsh
<#!
.SYNOPSIS
    Team-friendly wrapper for full network diagnostics.

.DESCRIPTION
    Runs scripts/full_network_diagnostics.ps1 using defaults defined in one place,
    while still allowing command-line overrides for any key parameter.

    Edit the DEFAULTS block below once for your environment, then run:
      ./scripts/run_diagnostics.ps1

.EXAMPLE
    ./scripts/run_diagnostics.ps1

.EXAMPLE
    ./scripts/run_diagnostics.ps1 -FabricWorkspaceId "11111111-1111-1111-1111-111111111111" -ManagedPrivateEndpointName "mpe-apim-dev01"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$PrivateLinkServiceName,

    [Parameter(Mandatory = $false)]
    [string]$LoadBalancerName,

    [Parameter(Mandatory = $false)]
    [string]$FabricWorkspaceId,

    [Parameter(Mandatory = $false)]
    [string]$ManagedPrivateEndpointName,

    [Parameter(Mandatory = $false)]
    [string[]]$Hostnames,

    [Parameter(Mandatory = $false)]
    [string]$TestUrl,

    [Parameter(Mandatory = $false)]
    [string]$VmResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$VmName,

    [Parameter(Mandatory = $false)]
    [string]$FabricToken,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [int]$TcpTimeoutMs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# DEFAULTS (edit once for your environment)
# ------------------------------------------------------------
$defaults = [ordered]@{
    SubscriptionId             = ""
    ResourceGroup              = "azapim-dev-rg"
    PrivateLinkServiceName     = "apim-dev-pls01"
    LoadBalancerName           = ""
    FabricWorkspaceId          = ""
    ManagedPrivateEndpointName = ""
    Hostnames                  = @("stc-poc-dev-apim.azure-api.net")
    TestUrl                    = ""
    VmResourceGroup            = "azapim-dev-rg"
    VmName                     = "fwd-apim-dev-vm"
    FabricToken                = ""
    OutputPath                 = ""
    TcpTimeoutMs               = 5000
}

function Pick-Value {
    param(
        [object]$Override,
        [object]$Default
    )

    if ($null -eq $Override) {
        return $Default
    }

    if ($Override -is [string] -and [string]::IsNullOrWhiteSpace($Override)) {
        return $Default
    }

    if ($Override -is [array] -and $Override.Count -eq 0) {
        return $Default
    }

    return $Override
}

$effective = [ordered]@{
    SubscriptionId             = Pick-Value -Override $SubscriptionId -Default $defaults.SubscriptionId
    ResourceGroup              = Pick-Value -Override $ResourceGroup -Default $defaults.ResourceGroup
    PrivateLinkServiceName     = Pick-Value -Override $PrivateLinkServiceName -Default $defaults.PrivateLinkServiceName
    LoadBalancerName           = Pick-Value -Override $LoadBalancerName -Default $defaults.LoadBalancerName
    FabricWorkspaceId          = Pick-Value -Override $FabricWorkspaceId -Default $defaults.FabricWorkspaceId
    ManagedPrivateEndpointName = Pick-Value -Override $ManagedPrivateEndpointName -Default $defaults.ManagedPrivateEndpointName
    Hostnames                  = Pick-Value -Override $Hostnames -Default $defaults.Hostnames
    TestUrl                    = Pick-Value -Override $TestUrl -Default $defaults.TestUrl
    VmResourceGroup            = Pick-Value -Override $VmResourceGroup -Default $defaults.VmResourceGroup
    VmName                     = Pick-Value -Override $VmName -Default $defaults.VmName
    FabricToken                = Pick-Value -Override $FabricToken -Default $defaults.FabricToken
    OutputPath                 = Pick-Value -Override $OutputPath -Default $defaults.OutputPath
    TcpTimeoutMs               = if ($PSBoundParameters.ContainsKey("TcpTimeoutMs")) { $TcpTimeoutMs } else { [int]$defaults.TcpTimeoutMs }
}

if ([string]::IsNullOrWhiteSpace([string]$effective.ResourceGroup)) {
    throw "ResourceGroup is required. Set it in defaults or pass -ResourceGroup."
}
if ([string]::IsNullOrWhiteSpace([string]$effective.PrivateLinkServiceName)) {
    throw "PrivateLinkServiceName is required. Set it in defaults or pass -PrivateLinkServiceName."
}

$scriptPath = Join-Path $PSScriptRoot "full_network_diagnostics.ps1"
if (-not (Test-Path -Path $scriptPath)) {
    throw "Missing script: $scriptPath"
}

Write-Host "Running full diagnostics with effective settings:" -ForegroundColor Cyan
Write-Host "- ResourceGroup: $($effective.ResourceGroup)" -ForegroundColor Gray
Write-Host "- PrivateLinkServiceName: $($effective.PrivateLinkServiceName)" -ForegroundColor Gray
Write-Host "- FabricWorkspaceId: $($effective.FabricWorkspaceId)" -ForegroundColor Gray
Write-Host "- ManagedPrivateEndpointName: $($effective.ManagedPrivateEndpointName)" -ForegroundColor Gray
Write-Host "- Hostnames: $([string]::Join(', ', $effective.Hostnames))" -ForegroundColor Gray
Write-Host "- VM: $($effective.VmResourceGroup)/$($effective.VmName)" -ForegroundColor Gray

$invokeParams = @{
    ResourceGroup          = $effective.ResourceGroup
    PrivateLinkServiceName = $effective.PrivateLinkServiceName
    Hostnames              = $effective.Hostnames
    TcpTimeoutMs           = $effective.TcpTimeoutMs
}

if (-not [string]::IsNullOrWhiteSpace([string]$effective.SubscriptionId)) { $invokeParams.SubscriptionId = $effective.SubscriptionId }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.LoadBalancerName)) { $invokeParams.LoadBalancerName = $effective.LoadBalancerName }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.FabricWorkspaceId)) { $invokeParams.FabricWorkspaceId = $effective.FabricWorkspaceId }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.ManagedPrivateEndpointName)) { $invokeParams.ManagedPrivateEndpointName = $effective.ManagedPrivateEndpointName }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.TestUrl)) { $invokeParams.TestUrl = $effective.TestUrl }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.VmResourceGroup) -and -not [string]::IsNullOrWhiteSpace([string]$effective.VmName)) {
    $invokeParams.VmResourceGroup = $effective.VmResourceGroup
    $invokeParams.VmName = $effective.VmName
}
if (-not [string]::IsNullOrWhiteSpace([string]$effective.FabricToken)) { $invokeParams.FabricToken = $effective.FabricToken }
if (-not [string]::IsNullOrWhiteSpace([string]$effective.OutputPath)) { $invokeParams.OutputPath = $effective.OutputPath }

& $scriptPath @invokeParams
