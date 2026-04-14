#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Create an Azure Service Principal and store credentials in Key Vault
.DESCRIPTION
    Creates a new Service Principal and adds its Client ID, Secret, and Tenant ID to Azure Key Vault
.PARAMETER KeyVaultName
    Name of the Key Vault (extracted from URL if not provided)
.PARAMETER KeyVaultUrl
    Full URL of the Key Vault (e.g., https://your-keyvault.vault.azure.net/)
.PARAMETER ServicePrincipalName
    Name for the new Service Principal
.PARAMETER TenantId
    Azure Tenant ID (optional, uses current context if not provided)
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultUrl = "https://your-keyvault.vault.azure.net/",
    
    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "fabric-hub-spoke-sp",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId = "<your-entra-tenant-id>"
)

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Service Principal Setup Script" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Extract Key Vault name from URL
$KeyVaultName = $KeyVaultUrl -replace "^https://", "" -replace "\.vault\.azure\.net/.*$", ""

Write-Host "`nConfiguration:" -ForegroundColor Green
Write-Host "  Key Vault Name: $KeyVaultName"
Write-Host "  Key Vault URL: $KeyVaultUrl"
Write-Host "  Service Principal Name: $ServicePrincipalName"
Write-Host "  Tenant ID: $TenantId"

# Step 1: Check Azure CLI/PowerShell login
Write-Host "`n[Step 1] Checking Azure authentication..." -ForegroundColor Yellow
try {
    $account = az account show --output json 2>$null | ConvertFrom-Json
    if ($null -eq $account) {
        Write-Host "Not authenticated. Please run 'az login'" -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Authenticated as: $($account.user.name)" -ForegroundColor Green
} catch {
    Write-Host "Error checking authentication: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Create Service Principal
Write-Host "`n[Step 2] Creating Service Principal..." -ForegroundColor Yellow
try {
    $subscriptionId = az account show --query id -o tsv
    Write-Host "  Using subscription: $subscriptionId" -ForegroundColor Cyan
    
    # Create Service Principal
    Write-Host "  Creating SP: $ServicePrincipalName..." -ForegroundColor Cyan
    $spOutput = @()
    az ad sp create-for-rbac `
        --name $ServicePrincipalName `
        --role Contributor `
        --scopes /subscriptions/$subscriptionId 2>&1 | Tee-Object -Variable spOutput | Out-Null
    
    # Join array output into string
    $spJson = $spOutput -join "`n"
    
    Write-Host "  Raw output length: $($spJson.Length) chars" -ForegroundColor Gray
    
    # Try to parse JSON
    $sp = $null
    try {
        $sp = $spJson | ConvertFrom-Json
    } catch {
        Write-Host "Warning: Could not parse JSON. Raw output:" -ForegroundColor Yellow
        Write-Host $spJson -ForegroundColor Cyan
        
        # Try to extract values from the output
        if ($spJson -match '"appId"\s*:\s*"([^"]+)"') {
            $clientId = $matches[1]
            Write-Host "Extracted Client ID: $clientId" -ForegroundColor Green
        }
        if ($spJson -match '"password"\s*:\s*"([^"]+)"') {
            $password = $matches[1]
            Write-Host "Extracted Password: ••••••••" -ForegroundColor Green
        }
        if ($spJson -match '"tenant"\s*:\s*"([^"]+)"') {
            $tenant = $matches[1]
            Write-Host "Extracted Tenant ID: $tenant" -ForegroundColor Green
        }
        
        if ([string]::IsNullOrEmpty($clientId)) {
            Write-Host "Failed to create or extract Service Principal details" -ForegroundColor Red
            exit 1
        }
        
        # Create object manually from extracted values
        $sp = [PSCustomObject]@{
            clientId = $clientId
            password = $password
            tenant   = $tenant
        }
    }
    
    if ($null -eq $sp.clientId) {
        Write-Host "Failed to create Service Principal" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✓ Service Principal created" -ForegroundColor Green
    Write-Host "  Client ID: $($sp.clientId)" -ForegroundColor Cyan
    Write-Host "  Tenant ID: $($sp.tenant)" -ForegroundColor Cyan
} catch {
    Write-Host "Error creating Service Principal: $_" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Step 3: Configure OBO (On-Behalf-Of) API Permissions
Write-Host "`n[Step 3] Configuring On-Behalf-Of (OBO) API Permissions..." -ForegroundColor Yellow
Write-Host "  Adding delegated permissions for OBO flow..." -ForegroundColor Cyan

try {
    # Azure SQL Database - user_impersonation (delegated)
    Write-Host "  • Adding Azure SQL Database permissions..." -ForegroundColor Cyan
    az ad app permission add `
        --id $sp.clientId `
        --api 022907d3-0f1b-48f7-badc-1ba6abab6d66 `
        --api-permissions c39ef2d1-04ce-46dc-8b5f-e9a5c60f0fc9=Scope `
        --output none 2>&1
    
    # Azure Service Management (ARM) - user_impersonation (delegated)
    Write-Host "  • Adding Azure Management API permissions..." -ForegroundColor Cyan
    az ad app permission add `
        --id $sp.clientId `
        --api 797f4846-ba00-4fd7-ba43-dac1f8f63013 `
        --api-permissions 41094075-9dad-400e-a0bd-54e686782033=Scope `
        --output none 2>&1
    
    # Power BI Service - Multiple delegated scopes
    Write-Host "  • Adding Power BI/Fabric API permissions..." -ForegroundColor Cyan
    az ad app permission add `
        --id $sp.clientId `
        --api 00000009-0000-0000-c000-000000000000 `
        --api-permissions 4ae1bf56-f562-4747-b7bc-2fa0874ed46f=Scope `
        --output none 2>&1  # Dataset.Read.All
    
    az ad app permission add `
        --id $sp.clientId `
        --api 00000009-0000-0000-c000-000000000000 `
        --api-permissions 7504609f-c495-4c64-8542-686125a5a36f=Scope `
        --output none 2>&1  # Dataset.ReadWrite.All
    
    az ad app permission add `
        --id $sp.clientId `
        --api 00000009-0000-0000-c000-000000000000 `
        --api-permissions 2448370f-f988-42cd-909c-6528efd67c1a=Scope `
        --output none 2>&1  # Workspace.Read.All
    
    az ad app permission add `
        --id $sp.clientId `
        --api 00000009-0000-0000-c000-000000000000 `
        --api-permissions 7f33e027-4039-419b-938e-2f8ca153e68e=Scope `
        --output none 2>&1  # Workspace.ReadWrite.All
    
    Write-Host "✓ Delegated API permissions added" -ForegroundColor Green
    
    # Grant admin consent
    Write-Host "`n  Granting admin consent for delegated permissions..." -ForegroundColor Cyan
    az ad app permission admin-consent --id $sp.clientId 2>&1 | Out-Null
    
    Write-Host "✓ Admin consent granted for OBO flow" -ForegroundColor Green
    Write-Host "  ✓ Azure SQL Database (user_impersonation)" -ForegroundColor Green
    Write-Host "  ✓ Azure Management API (user_impersonation)" -ForegroundColor Green
    Write-Host "  ✓ Power BI Service (Dataset.Read.All, Dataset.ReadWrite.All)" -ForegroundColor Green
    Write-Host "  ✓ Power BI Service (Workspace.Read.All, Workspace.ReadWrite.All)" -ForegroundColor Green
    
} catch {
    Write-Host "⚠ Warning: Could not configure API permissions automatically: $_" -ForegroundColor Yellow
    Write-Host "   Please manually add delegated permissions in Azure Portal:" -ForegroundColor Yellow
    Write-Host "   1. Go to Entra ID → App registrations → $ServicePrincipalName" -ForegroundColor Yellow
    Write-Host "   2. Click 'API permissions' → 'Add a permission'" -ForegroundColor Yellow
    Write-Host "   3. Add DELEGATED permissions for:" -ForegroundColor Yellow
    Write-Host "      • Azure SQL Database: user_impersonation" -ForegroundColor Yellow
    Write-Host "      • Azure Service Management: user_impersonation" -ForegroundColor Yellow
    Write-Host "      • Power BI Service: Dataset.Read.All, Workspace.Read.All" -ForegroundColor Yellow
    Write-Host "   4. Click 'Grant admin consent'" -ForegroundColor Yellow
}

# Step 4: Store secrets in Key Vault
Write-Host "`n[Step 4] Storing secrets in Key Vault..." -ForegroundColor Yellow

$secrets = @{
    "sp-client-id"   = $sp.clientId
    "sp-client-secret" = $sp.password
    "sp-tenant-id"   = $sp.tenant
}

foreach ($secretName in $secrets.Keys) {
    try {
        $value = $secrets[$secretName]
        az keyvault secret set `
            --vault-name $KeyVaultName `
            --name $secretName `
            --value $value `
            --output none 2>&1
        
        Write-Host "✓ Secret '$secretName' stored in Key Vault" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to store secret '$secretName': $_" -ForegroundColor Red
        exit 1
    }
}

# Step 5: Grant Key Vault access to the Service Principal using RBAC
Write-Host "`n[Step 5] Configuring Key Vault access (RBAC)..." -ForegroundColor Yellow
try {
    # Get Key Vault resource ID
    $kvResourceId = az keyvault show --name $KeyVaultName --query id -o tsv
    
    # Assign "Key Vault Secrets User" role to Service Principal
    # This role allows reading secrets (get/list)
    az role assignment create `
        --role "Key Vault Secrets User" `
        --assignee $sp.clientId `
        --scope $kvResourceId `
        --output none 2>&1
    
    Write-Host "✓ Service Principal granted 'Key Vault Secrets User' role" -ForegroundColor Green
    Write-Host "  (RBAC-enabled Key Vault)" -ForegroundColor Cyan
} catch {
    Write-Host "⚠ Warning: Could not assign RBAC role: $_" -ForegroundColor Yellow
    Write-Host "   Please manually assign 'Key Vault Secrets User' role to the Service Principal in Azure Portal" -ForegroundColor Yellow
}

# Step 6: Summary
Write-Host "`n================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

Write-Host "`nService Principal Details:" -ForegroundColor Cyan
Write-Host "  Client ID: $($sp.clientId)"
Write-Host "  Tenant ID: $($sp.tenant)"
Write-Host "  Client Secret: ••••••••••• (stored in Key Vault)"

Write-Host "`nOBO (On-Behalf-Of) Configuration:" -ForegroundColor Cyan
Write-Host "  ✓ Azure SQL Database - user_impersonation (delegated)"
Write-Host "  ✓ Azure Management API - user_impersonation (delegated)"
Write-Host "  ✓ Power BI/Fabric API - Multiple delegated scopes"
Write-Host "  ✓ Admin consent granted"

Write-Host "`nKey Vault Secrets Created:" -ForegroundColor Cyan
Write-Host "  • sp-client-id"
Write-Host "  • sp-client-secret"
Write-Host "  • sp-tenant-id"

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Update local.settings.json with your Key Vault URL (if not already done)"
Write-Host "  2. The secrets are now available for your Azure Function to use"
Write-Host "  3. For Power BI: Add this SP to workspace members in Fabric portal"
Write-Host "  4. For Azure SQL: Grant database-level permissions (db_datareader, etc.)"
Write-Host "  5. Keep the password safe: $($sp.password)"

Write-Host ""
