<#
.SYNOPSIS
    Deploys the secure web app baseline from start to finish.

.DESCRIPTION
    1. Confirms you are signed in to the Azure CLI
    2. Makes you (the signed-in user) the Microsoft Entra admin for Azure SQL
    3. Creates the resource group
    4. Shows a what-if preview of every change and asks you to confirm
    5. Deploys infra/main.bicep
    6. Grants the web app's managed identity access to the database
    7. Runs the security baseline tests against what was deployed

.PARAMETER ResourceGroup
    Resource group to deploy into. Created if it does not exist.

.PARAMETER AppName
    Short lowercase prefix for resource names (3-12 letters/numbers, starts with a letter).

.PARAMETER Environment
    dev or prod. Controls sizes, log retention and Key Vault purge protection.

.PARAMETER Location
    Azure region, e.g. eastus or centralus.

.PARAMETER Force
    Skip the confirmation prompt (useful in pipelines).

.PARAMETER SkipTests
    Skip the post-deployment security tests.

.EXAMPLE
    ./scripts/Deploy.ps1 -ResourceGroup rg-donorportal-dev -AppName donorportal

.EXAMPLE
    ./scripts/Deploy.ps1 -ResourceGroup rg-donorportal-prod -AppName donorportal -Environment prod -Location centralus
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z][a-z0-9]{2,11}$')]
    [string]$AppName,

    [ValidateSet('dev', 'prod')]
    [string]$Environment = 'dev',

    [string]$Location = 'eastus',

    [switch]$Force,

    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AzCli.ps1')

$repoRoot = Split-Path $PSScriptRoot -Parent
$template = Join-Path $repoRoot 'infra/main.bicep'

# --- 1. Sign-in check ---------------------------------------------------------
Write-Step 'Checking Azure CLI sign-in'
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI not found. Install it from https://aka.ms/installazurecli and run "az login".'
}
$account = Invoke-AzCli 'account', 'show'
Write-Host "Subscription: $($account.name) ($($account.id))"

# --- 2. Who is the SQL admin? -------------------------------------------------
Write-Step 'Looking up your Microsoft Entra identity (becomes the SQL admin)'
$me = Invoke-AzCli 'ad', 'signed-in-user', 'show', '--query', '{id:id,upn:userPrincipalName}'
Write-Host "SQL Entra admin: $($me.upn)"

$parameters = @(
    "appName=$AppName"
    "environment=$Environment"
    "sqlEntraAdminLogin=$($me.upn)"
    "sqlEntraAdminObjectId=$($me.id)"
    'sqlEntraAdminPrincipalType=User'
)

# --- 3. Resource group --------------------------------------------------------
Write-Step "Creating resource group '$ResourceGroup' in $Location"
$null = Invoke-AzCli 'group', 'create', '--name', $ResourceGroup, '--location', $Location,
    '--tags', 'project=secure-webapp-baseline', "environment=$Environment"

# --- 4. Preview ---------------------------------------------------------------
Write-Step 'Previewing changes (what-if)'
& az deployment group what-if --resource-group $ResourceGroup --template-file $template --parameters @parameters --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'What-if failed. Fix the errors above before deploying.' }

if (-not $Force) {
    $answer = Read-Host 'Deploy these changes? (y/N)'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host 'Cancelled. Nothing was deployed.' -ForegroundColor Yellow
        return
    }
}

# --- 5. Deploy ----------------------------------------------------------------
$deploymentName = "baseline-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Step "Deploying ($deploymentName). This usually takes 4-8 minutes"
$deployArgs = @(
    'deployment', 'group', 'create',
    '--resource-group', $ResourceGroup,
    '--name', $deploymentName,
    '--template-file', $template,
    '--parameters'
) + $parameters + @('--query', 'properties.outputs')
$outputs = Invoke-AzCli $deployArgs

$webAppName = $outputs.webAppName.value
$sqlServerName = $outputs.sqlServerName.value
$databaseName = $outputs.sqlDatabaseName.value

# --- 6. Database access for the app's managed identity ------------------------
Write-Step 'Granting the web app identity access to the database'
& (Join-Path $PSScriptRoot 'Grant-AppDatabaseAccess.ps1') `
    -ResourceGroup $ResourceGroup `
    -SqlServerName $sqlServerName `
    -DatabaseName $databaseName `
    -AppIdentityName $webAppName

# --- 7. Verify ----------------------------------------------------------------
if (-not $SkipTests) {
    Write-Step 'Running security baseline tests'
    & (Join-Path $PSScriptRoot 'Test-SecurityBaseline.ps1') -ResourceGroup $ResourceGroup
}

Write-Step 'Done'
Write-Host "Web app:    $($outputs.webAppUrl.value)"
Write-Host "Key Vault:  $($outputs.keyVaultName.value)"
Write-Host "SQL server: $($outputs.sqlServerFqdn.value)"
Write-Host "Logs:       $($outputs.logAnalyticsWorkspaceName.value)"
Write-Host ''
Write-Host "To delete everything when you're finished (stops all charges):" -ForegroundColor Yellow
Write-Host "  az group delete --name $ResourceGroup --yes --no-wait"
