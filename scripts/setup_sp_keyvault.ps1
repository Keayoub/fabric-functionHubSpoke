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
    [string]$TenantId = "c869cf92-11d8-4fbc-a7cf-6114d160dd71"
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

# Step 3: Store secrets in Key Vault
Write-Host "`n[Step 3] Storing secrets in Key Vault..." -ForegroundColor Yellow

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

# Step 4: Grant Key Vault access to the Service Principal using RBAC
Write-Host "`n[Step 4] Configuring Key Vault access (RBAC)..." -ForegroundColor Yellow
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

# Step 5: Summary
Write-Host "`n================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

Write-Host "`nService Principal Details:" -ForegroundColor Cyan
Write-Host "  Client ID: $($sp.clientId)"
Write-Host "  Tenant ID: $($sp.tenant)"
Write-Host "  Client Secret: ••••••••••• (stored in Key Vault)"

Write-Host "`nKey Vault Secrets Created:" -ForegroundColor Cyan
Write-Host "  • sp-client-id"
Write-Host "  • sp-client-secret"
Write-Host "  • sp-tenant-id"

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Update local.settings.json with your Key Vault URL (if not already done)"
Write-Host "  2. The secrets are now available for your Azure Function to use"
Write-Host "  3. Keep the password safe: $($sp.password)"

Write-Host ""
