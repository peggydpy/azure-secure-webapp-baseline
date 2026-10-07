# Shared helpers for calling the Azure CLI from PowerShell.
# Dot-source this file:  . "$PSScriptRoot/AzCli.ps1"

function Invoke-AzCli {
    <#
    .SYNOPSIS
        Runs an Azure CLI command and returns its JSON output as PowerShell objects.
        Throws if the command fails, so scripts stop instead of continuing on bad data.
    .EXAMPLE
        Invoke-AzCli 'webapp', 'show', '-g', 'rg-demo', '-n', 'app-demo'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Arguments
    )

    $output = & az @Arguments --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }

    $text = ($output -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    # Assign first, then return: this unrolls JSON arrays the same way on PowerShell 5.1 and 7
    $result = ConvertFrom-Json -InputObject $text
    return $result
}

function Invoke-AzCliText {
    <#
    .SYNOPSIS
        Runs an Azure CLI command and returns plain text (for single values like tokens or names).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Arguments
    )

    $output = & az @Arguments --only-show-errors --output tsv
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments[0..1] -join ' ') ..."
    }
    return ($output -join "`n").Trim()
}

function Write-Step {
    <#
    .SYNOPSIS
        Prints a visible section header in the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}
