<#
.SYNOPSIS
    Gives the web app's managed identity least-privilege access to the database.

.DESCRIPTION
    Azure SQL in this baseline only accepts Microsoft Entra ID logins, so the app needs
    a database user mapped to its managed identity. This can't be done in Bicep; it
    takes a T-SQL command run by the SQL Entra admin (you).

    For safety the script:
      - opens the SQL firewall to YOUR current IP only, and only while it runs
      - signs in with a short-lived Entra token (no SQL password exists)
      - is idempotent: re-running it does not create duplicates
      - always removes the temporary firewall rule, even if something fails

.PARAMETER Roles
    Database roles to grant. Defaults to read + write (no schema changes, no admin).

.EXAMPLE
    ./scripts/Grant-AppDatabaseAccess.ps1 -ResourceGroup rg-donorportal-dev `
        -SqlServerName sql-donorportal-dev-abc123 -DatabaseName appdb `
        -AppIdentityName app-donorportal-dev-abc123
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$SqlServerName,

    [Parameter(Mandatory)]
    [string]$DatabaseName,

    # System-assigned managed identities are named after their web app
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]{2,60}$')]
    [string]$AppIdentityName,

    [ValidateSet('db_datareader', 'db_datawriter', 'db_ddladmin')]
    [string[]]$Roles = @('db_datareader', 'db_datawriter')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AzCli.ps1')

# Parameterized T-SQL. QUOTENAME guards against injection in the dynamic statements.
$grantSql = @'
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @principal)
BEGIN
    DECLARE @create nvarchar(400) = N'CREATE USER ' + QUOTENAME(@principal) + N' FROM EXTERNAL PROVIDER;';
    EXEC sp_executesql @create;
END;

IF ISNULL(IS_ROLEMEMBER(@role, @principal), 0) = 0
BEGIN
    DECLARE @grant nvarchar(400) = N'ALTER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@principal) + N';';
    EXEC sp_executesql @grant;
END;
'@

$fqdn = Invoke-AzCliText 'sql', 'server', 'show', '-g', $ResourceGroup, '-n', $SqlServerName, '--query', 'fullyQualifiedDomainName'
$myIp = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 15).ToString().Trim()
$ruleName = "temp-deployer-$(Get-Date -Format 'yyyyMMddHHmmss')"

Write-Host "Opening SQL firewall for $myIp (temporary rule '$ruleName')"
$null = Invoke-AzCli 'sql', 'server', 'firewall-rule', 'create',
    '-g', $ResourceGroup, '-s', $SqlServerName, '-n', $ruleName,
    '--start-ip-address', $myIp, '--end-ip-address', $myIp

try {
    $token = Invoke-AzCliText 'account', 'get-access-token', '--resource', 'https://database.windows.net/', '--query', 'accessToken'

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = "Server=tcp:$fqdn,1433;Database=$DatabaseName;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
    $connection.AccessToken = $token

    # New firewall rules can take a few seconds to apply, so retry the first connection.
    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $connection.Open()
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) { throw }
            Write-Host "  Waiting for firewall rule to apply (attempt $attempt of $maxAttempts)..."
            Start-Sleep -Seconds 10
        }
    }

    try {
        foreach ($role in $Roles) {
            $command = $connection.CreateCommand()
            $command.CommandText = $grantSql
            $null = $command.Parameters.AddWithValue('@principal', $AppIdentityName)
            $null = $command.Parameters.AddWithValue('@role', $role)
            $null = $command.ExecuteNonQuery()
            Write-Host "  $AppIdentityName -> $role" -ForegroundColor Green
        }
    }
    finally {
        $connection.Dispose()
    }
}
finally {
    Write-Host "Removing temporary firewall rule '$ruleName'"
    & az sql server firewall-rule delete -g $ResourceGroup -s $SqlServerName -n $ruleName --only-show-errors
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not remove firewall rule '$ruleName'. Delete it manually in the portal."
    }
}

Write-Host 'Database access granted.' -ForegroundColor Green
