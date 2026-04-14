#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Quick OBO setup checker - verifies both Function App and SP are configured
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppClientId,
    
    [Parameter(Mandatory = $true)]
    [string]$ServicePrincipalClientId
)

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "OBO Configuration Checker" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$allGood = $true

# Check 1: Function App - Expose an API
Write-Host "`n[1] Checking Function App API Exposure..." -ForegroundColor Yellow
Write-Host "    App ID: $FunctionAppClientId" -ForegroundColor Gray

try {
    $funcApp = az ad app show --id $FunctionAppClientId --output json | ConvertFrom-Json
    
    # Check if application ID URI is set
    if ($funcApp.identifierUris -and $funcApp.identifierUris.Count -gt 0) {
        Write-Host "    ✓ Application ID URI configured: $($funcApp.identifierUris[0])" -ForegroundColor Green
    } else {
        Write-Host "    ✗ NO Application ID URI found!" -ForegroundColor Red
        Write-Host "      → Go to: Entra ID → App registrations → $FunctionAppClientId" -ForegroundColor Yellow
        Write-Host "      → Click 'Expose an API' → Set Application ID URI to: api://$FunctionAppClientId" -ForegroundColor Yellow
        $allGood = $false
    }
    
    # Check if user_impersonation scope is exposed
    if ($funcApp.api.oauth2PermissionScopes -and $funcApp.api.oauth2PermissionScopes.Count -gt 0) {
        $userImpScope = $funcApp.api.oauth2PermissionScopes | Where-Object { $_.value -eq "user_impersonation" }
        if ($userImpScope) {
            Write-Host "    ✓ 'user_impersonation' scope exposed" -ForegroundColor Green
        } else {
            Write-Host "    ⚠ Scopes found, but 'user_impersonation' missing" -ForegroundColor Yellow
            Write-Host "      → Add scope: user_impersonation (delegated)" -ForegroundColor Yellow
            $allGood = $false
        }
    } else {
        Write-Host "    ✗ NO scopes exposed!" -ForegroundColor Red
        Write-Host "      → Go to: Entra ID → App registrations → $FunctionAppClientId" -ForegroundColor Yellow
        Write-Host "      → Click 'Expose an API' → 'Add a scope' → Name it 'user_impersonation'" -ForegroundColor Yellow
        $allGood = $false
    }
} catch {
    Write-Host "    ✗ Failed to query Function App: $_" -ForegroundColor Red
    $allGood = $false
}

# Check 2: Service Principal - Delegated Permissions
Write-Host "`n[2] Checking Service Principal Delegated Permissions..." -ForegroundColor Yellow
Write-Host "    SP Client ID: $ServicePrincipalClientId" -ForegroundColor Gray

try {
    $spApp = az ad app show --id $ServicePrincipalClientId --output json | ConvertFrom-Json
    $permissions = az ad app permission list --id $ServicePrincipalClientId --output json | ConvertFrom-Json
    
    # Define expected delegated permissions
    $expected = @{
        "022907d3-0f1b-48f7-badc-1ba6abab6d66" = @{name = "Azure SQL Database"; perms = @("c39ef2d1-04ce-46dc-8b5f-e9a5c60f0fc9")}
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" = @{name = "Azure Management API"; perms = @("41094075-9dad-400e-a0bd-54e686782033")}
        "00000009-0000-0000-c000-000000000000" = @{name = "Power BI Service"; perms = @("4ae1bf56-f562-4747-b7bc-2fa0874ed46f")}
    }
    
    $foundCount = 0
    foreach ($apiId in $expected.Keys) {
        $apiPerms = $permissions | Where-Object { $_.resourceAppId -eq $apiId }
        if ($apiPerms) {
            $delegatedPerms = $apiPerms.resourceAccess | Where-Object { $_.type -eq "Scope" }
            if ($delegatedPerms.Count -gt 0) {
                Write-Host "    ✓ $($expected[$apiId].name) - Delegated permissions configured" -ForegroundColor Green
                $foundCount++
            }
        }
    }
    
    if ($foundCount -eq 0) {
        Write-Host "    ✗ NO delegated permissions found!" -ForegroundColor Red
        Write-Host "      → Run: .\scripts\setup_sp_keyvault.ps1 to configure automatically" -ForegroundColor Yellow
        Write-Host "      → Or manually add in Azure Portal:" -ForegroundColor Yellow
        Write-Host "        Entra ID → App registrations → $ServicePrincipalClientId → API permissions" -ForegroundColor Yellow
        $allGood = $false
    } elseif ($foundCount -lt 3) {
        Write-Host "    ⚠ Only $foundCount/3 APIs configured" -ForegroundColor Yellow
        $allGood = $false
    }
    
    # Check admin consent
    Write-Host "`n[3] Checking Admin Consent..." -ForegroundColor Yellow
    $spObject = az ad sp list --filter "appId eq '$ServicePrincipalClientId'" --output json | ConvertFrom-Json
    if ($spObject.Count -gt 0) {
        $grants = az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($spObject[0].id)'" 2>$null | ConvertFrom-Json
        if ($grants.value -and $grants.value.Count -gt 0) {
            Write-Host "    ✓ Admin consent granted" -ForegroundColor Green
        } else {
            Write-Host "    ✗ Admin consent NOT granted!" -ForegroundColor Red
            Write-Host "      → Run: az ad app permission admin-consent --id $ServicePrincipalClientId" -ForegroundColor Yellow
            $allGood = $false
        }
    }
    
} catch {
    Write-Host "    ✗ Failed to query Service Principal: $_" -ForegroundColor Red
    $allGood = $false
}

# Summary
Write-Host "`n================================" -ForegroundColor Cyan
if ($allGood) {
    Write-Host "✓ OBO CONFIGURATION LOOKS GOOD!" -ForegroundColor Green
    Write-Host "Your passthrough flow should work" -ForegroundColor Green
} else {
    Write-Host "✗ OBO CONFIGURATION INCOMPLETE" -ForegroundColor Red
    Write-Host "Follow the fix instructions above" -ForegroundColor Yellow
}
Write-Host "================================`n" -ForegroundColor Cyan
