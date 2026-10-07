<#
.SYNOPSIS
    Checks a deployed environment against the security baseline and reports PASS / WARN / FAIL.

.DESCRIPTION
    Infrastructure-as-code says what SHOULD be deployed. This script checks what IS
    deployed, which catches drift (someone changing a setting in the portal later).

    It reads settings with the Azure CLI only. It never changes anything.
    Exit code 0 = no failures, 1 = at least one control failed.

.EXAMPLE
    ./scripts/Test-SecurityBaseline.ps1 -ResourceGroup rg-donorportal-dev
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AzCli.ps1')

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Area,
        [string]$Control,
        [ValidateSet('PASS', 'WARN', 'FAIL')]
        [string]$Result,
        [string]$Detail = ''
    )
    $results.Add([pscustomobject]@{
            Area    = $Area
            Control = $Control
            Result  = $Result
            Detail  = $Detail
        })
}

function Test-Control {
    # PASS when the condition is true, otherwise FAIL (or WARN when -WarnOnly)
    param(
        [string]$Area,
        [string]$Control,
        [bool]$Condition,
        [string]$Detail = '',
        [switch]$WarnOnly
    )
    if ($Condition) {
        Add-Result $Area $Control 'PASS' $Detail
    }
    elseif ($WarnOnly) {
        Add-Result $Area $Control 'WARN' $Detail
    }
    else {
        Add-Result $Area $Control 'FAIL' $Detail
    }
}

function Test-TlsAtLeast12 {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $false }
    return ([version]$Version) -ge ([version]'1.2')
}

function Get-DiagnosticSettingCount {
    param([string]$ResourceId)
    $settings = Invoke-AzCli 'monitor', 'diagnostic-settings', 'list', '--resource', $ResourceId
    # Older CLI versions wrap the list in a "value" property
    if ($null -ne $settings -and $settings.PSObject.Properties.Name -contains 'value') {
        $settings = $settings.value
    }
    return @($settings).Where({ $null -ne $_ }).Count
}

$resources = @(Invoke-AzCli 'resource', 'list', '-g', $ResourceGroup, '--query', '[].{id:id,name:name,type:type}')
if ($resources.Count -eq 0) {
    throw "No resources found in resource group '$ResourceGroup'."
}

# --- App Service --------------------------------------------------------------
foreach ($site in $resources.Where({ $_.type -eq 'Microsoft.Web/sites' })) {
    $area = "Web app: $($site.name)"
    $app = Invoke-AzCli 'webapp', 'show', '-g', $ResourceGroup, '-n', $site.name
    $config = Invoke-AzCli 'webapp', 'config', 'show', '-g', $ResourceGroup, '-n', $site.name

    Test-Control $area 'HTTPS only' ($app.httpsOnly -eq $true)
    Test-Control $area 'Minimum TLS 1.2' (Test-TlsAtLeast12 $config.minTlsVersion) "minTlsVersion=$($config.minTlsVersion)"
    Test-Control $area 'FTP/FTPS disabled' ($config.ftpsState -eq 'Disabled') "ftpsState=$($config.ftpsState)"
    Test-Control $area 'Remote debugging off' ($config.remoteDebuggingEnabled -ne $true)
    Test-Control $area 'Managed identity enabled' ("$($app.identity.type)" -match 'SystemAssigned')

    foreach ($policy in 'ftp', 'scm') {
        $basicAuth = Invoke-AzCli 'resource', 'show', '--ids', "$($site.id)/basicPublishingCredentialsPolicies/$policy"
        Test-Control $area "Basic auth disabled ($policy)" ($basicAuth.properties.allow -eq $false)
    }

    $settings = @(Invoke-AzCli 'webapp', 'config', 'appsettings', 'list', '-g', $ResourceGroup, '-n', $site.name)
    $plainPasswords = @($settings.Where({ "$($_.value)" -match '(?i)(password|pwd)\s*=' }))
    Test-Control $area 'No passwords in app settings' ($plainPasswords.Count -eq 0) (($plainPasswords | ForEach-Object name) -join ', ')

    $secretNamed = @($settings.Where({ $_.name -match '(?i)(secret|key|token)' -and $_.name -ne 'APPLICATIONINSIGHTS_CONNECTION_STRING' }))
    $notInVault = @($secretNamed.Where({ "$($_.value)" -notmatch '^@Microsoft\.KeyVault\(' }))
    Test-Control $area 'Secret-like settings use Key Vault references' ($notInVault.Count -eq 0) (($notInVault | ForEach-Object name) -join ', ') -WarnOnly

    $diagCount = Get-DiagnosticSettingCount $site.id
    Test-Control $area 'Logs sent to Log Analytics' ($diagCount -gt 0) "$diagCount diagnostic setting(s)"
}

# --- Azure SQL ----------------------------------------------------------------
foreach ($server in $resources.Where({ $_.type -eq 'Microsoft.Sql/servers' })) {
    $area = "SQL: $($server.name)"
    $sql = Invoke-AzCli 'sql', 'server', 'show', '-g', $ResourceGroup, '-n', $server.name
    $adOnly = Invoke-AzCli 'sql', 'server', 'ad-only-auth', 'get', '-g', $ResourceGroup, '-n', $server.name
    $audit = Invoke-AzCli 'sql', 'server', 'audit-policy', 'show', '-g', $ResourceGroup, '-n', $server.name
    $rules = @(Invoke-AzCli 'sql', 'server', 'firewall-rule', 'list', '-g', $ResourceGroup, '-s', $server.name)

    Test-Control $area 'Minimum TLS 1.2' (Test-TlsAtLeast12 $sql.minimalTlsVersion) "minimalTlsVersion=$($sql.minimalTlsVersion)"
    Test-Control $area 'Entra-only authentication (no SQL passwords)' ($adOnly.azureAdOnlyAuthentication -eq $true)
    Test-Control $area 'Auditing enabled' ($audit.state -eq 'Enabled') "state=$($audit.state)"

    $openToInternet = @($rules.Where({ $_.startIpAddress -ne '0.0.0.0' -and $_.endIpAddress -eq '255.255.255.255' }))
    Test-Control $area 'No firewall rule open to the whole internet' ($openToInternet.Count -eq 0) (($openToInternet | ForEach-Object name) -join ', ')

    $leftover = @($rules.Where({ $_.name -like 'temp-deployer-*' }))
    Test-Control $area 'No leftover temporary firewall rules' ($leftover.Count -eq 0) (($leftover | ForEach-Object name) -join ', ') -WarnOnly
}

# --- Key Vault ----------------------------------------------------------------
foreach ($vault in $resources.Where({ $_.type -eq 'Microsoft.KeyVault/vaults' })) {
    $area = "Key Vault: $($vault.name)"
    $kv = Invoke-AzCli 'keyvault', 'show', '-g', $ResourceGroup, '-n', $vault.name

    Test-Control $area 'RBAC authorization (no access policies)' ($kv.properties.enableRbacAuthorization -eq $true)
    Test-Control $area 'Soft delete enabled' ($kv.properties.enableSoftDelete -ne $false)
    Test-Control $area 'Purge protection enabled' ($kv.properties.enablePurgeProtection -eq $true) 'Expected OFF in dev, ON in prod' -WarnOnly

    $diagCount = Get-DiagnosticSettingCount $vault.id
    Test-Control $area 'Audit logs sent to Log Analytics' ($diagCount -gt 0) "$diagCount diagnostic setting(s)"
}

# --- Report -------------------------------------------------------------------
$results | Format-Table -AutoSize -Wrap | Out-Host

$failCount = @($results.Where({ $_.Result -eq 'FAIL' })).Count
$warnCount = @($results.Where({ $_.Result -eq 'WARN' })).Count
$passCount = @($results.Where({ $_.Result -eq 'PASS' })).Count

$color = if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "Summary: $passCount passed, $warnCount warnings, $failCount failed" -ForegroundColor $color

if ($failCount -gt 0) {
    exit 1
}
