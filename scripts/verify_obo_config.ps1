#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Verify OBO (On-Behalf-Of) configuration for Service Principal
.DESCRIPTION
    Checks if the Service Principal has required delegated permissions for OBO flow
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultUrl = "https://your-keyvault.vault.azure.net/",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = ""
)

Write-Host "================================" -ForegroundColor Cyan
Write-Host "OBO Configuration Verification" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Extract Key Vault name from URL if not provided
if ([string]::IsNullOrEmpty($KeyVaultName)) {
    $KeyVaultName = $KeyVaultUrl -replace "^https://", "" -replace "\.vault\.azure\.net/.*$", ""
}

Write-Host "`n[Step 1] Fetching Service Principal Client ID from Key Vault..." -ForegroundColor Yellow

try {
    $spClientId = az keyvault secret show --vault-name $KeyVaultName --name "sp-client-id" --query value -o tsv
    
    if ([string]::IsNullOrEmpty($spClientId)) {
        Write-Host "✗ SP Client ID not found in Key Vault" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✓ SP Client ID: $spClientId" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to fetch SP from Key Vault: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n[Step 2] Checking API Permissions..." -ForegroundColor Yellow

# Get current permissions
$permissions = az ad app permission list --id $spClientId --output json | ConvertFrom-Json

Write-Host "`nCurrent API Permissions:" -ForegroundColor Cyan

# Define required delegated permissions
$requiredPerms = @{
    "Azure SQL Database" = @{
        "resourceAppId" = "022907d3-0f1b-48f7-badc-1ba6abab6d66"
        "permissions" = @("c39ef2d1-04ce-46dc-8b5f-e9a5c60f0fc9") # user_impersonation
    }
    "Azure Service Management" = @{
        "resourceAppId" = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        "permissions" = @("41094075-9dad-400e-a0bd-54e686782033") # user_impersonation
    }
    "Power BI Service" = @{
        "resourceAppId" = "00000009-0000-0000-c000-000000000000"
        "permissions" = @(
            "4ae1bf56-f562-4747-b7bc-2fa0874ed46f", # Dataset.Read.All
            "7504609f-c495-4c64-8542-686125a5a36f", # Dataset.ReadWrite.All
            "2448370f-f988-42cd-909c-6528efd67c1a", # Workspace.Read.All
            "7f33e027-4039-419b-938e-2f8ca153e68e"  # Workspace.ReadWrite.All
        )
    }
}

$missingPerms = @()
$allConfigured = $true

foreach ($apiName in $requiredPerms.Keys) {
    $apiConfig = $requiredPerms[$apiName]
    $resourceAppId = $apiConfig.resourceAppId
    
    # Find permissions for this resource
    $apiPerms = $permissions | Where-Object { $_.resourceAppId -eq $resourceAppId }
    
    if ($null -eq $apiPerms) {
        Write-Host "  ✗ $apiName - NO PERMISSIONS CONFIGURED" -ForegroundColor Red
        $missingPerms += $apiName
        $allConfigured = $false
        continue
    }
    
    # Check each required permission
    $configuredScopes = $apiPerms.resourceAccess | Where-Object { $_.type -eq "Scope" } | Select-Object -ExpandProperty id
    $missingScopes = @()
    
    foreach ($permId in $apiConfig.permissions) {
        if ($permId -notin $configuredScopes) {
            $missingScopes += $permId
        }
    }
    
    if ($missingScopes.Count -eq 0) {
        Write-Host "  ✓ $apiName - All delegated permissions configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ $apiName - Missing $($missingScopes.Count) permission(s)" -ForegroundColor Yellow
        $allConfigured = $false
    }
}

Write-Host "`n[Step 3] Checking Admin Consent Status..." -ForegroundColor Yellow

# Check if admin consent has been granted
$spObject = az ad sp list --filter "appId eq '$spClientId'" --output json | ConvertFrom-Json

if ($spObject.Count -eq 0) {
    Write-Host "✗ Service Principal not found in directory" -ForegroundColor Red
    exit 1
}

$oauth2PermissionGrants = az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($spObject[0].id)'" | ConvertFrom-Json

if ($oauth2PermissionGrants.value.Count -gt 0) {
    Write-Host "✓ Admin consent granted" -ForegroundColor Green
    Write-Host "  Granted scopes:" -ForegroundColor Cyan
    foreach ($grant in $oauth2PermissionGrants.value) {
        Write-Host "    - $($grant.scope)" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠ No admin consent grants found" -ForegroundColor Yellow
    Write-Host "  Admin consent may not have been granted yet" -ForegroundColor Yellow
    $allConfigured = $false
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "Verification Summary" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

if ($allConfigured) {
    Write-Host "`n✓ OBO FLOW IS READY!" -ForegroundColor Green
    Write-Host "  Your Service Principal has all required delegated permissions" -ForegroundColor Green
    Write-Host "  The GetPassthroughToken endpoint should work for USER callers" -ForegroundColor Green
} else {
    Write-Host "`n✗ OBO FLOW NOT READY" -ForegroundColor Red
    Write-Host "  Missing required delegated permissions" -ForegroundColor Yellow
    Write-Host "`nTo fix, run:" -ForegroundColor Yellow
    Write-Host "  .\scripts\setup_sp_keyvault.ps1 -KeyVaultUrl '$KeyVaultUrl'" -ForegroundColor Cyan
    Write-Host "`nOr configure manually in Azure Portal:" -ForegroundColor Yellow
    Write-Host "  1. Go to Entra ID → App registrations → $spClientId" -ForegroundColor Gray
    Write-Host "  2. Click 'API permissions' → 'Add a permission'" -ForegroundColor Gray
    Write-Host "  3. Add these DELEGATED permissions:" -ForegroundColor Gray
    Write-Host "     • Azure SQL Database: user_impersonation" -ForegroundColor Gray
    Write-Host "     • Azure Service Management: user_impersonation" -ForegroundColor Gray
    Write-Host "     • Power BI Service: Dataset.Read/Write.All, Workspace.Read/Write.All" -ForegroundColor Gray
    Write-Host "  4. Click 'Grant admin consent'" -ForegroundColor Gray
}

Write-Host ""
