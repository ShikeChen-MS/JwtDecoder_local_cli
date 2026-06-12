<#
.SYNOPSIS
    Install the JwtDecoder PowerShell module from this packaged artifact.

.DESCRIPTION
    OFFLINE installer that ships inside the JwtDecoder PowerShell module
    artifact zip produced by the "Package PowerShell module" workflow. It
    does NOT build anything and never hits the network — it just copies
    the pre-built module files from the sibling "Module" folder into the
    user's (or machine's) PowerShell module path so PowerShell can auto-
    discover the module via Import-Module.

    The script fails fast on unsupported PowerShell: it requires
    PowerShell 7.4 or later, Core edition. Windows PowerShell 5.1 is
    explicitly rejected.

.PARAMETER Scope
    CurrentUser (default) installs to the per-user PowerShell module path.
    AllUsers    installs to the machine-wide path (needs admin / sudo).

.PARAMETER Force
    Overwrite an existing install at the same version.

.PARAMETER Path
    Override the path to the packaged module folder. Defaults to the
    sibling "Module" directory next to this script.

.EXAMPLE
    pwsh ./Install-PackagedModule.ps1
    Install for the current user.

.EXAMPLE
    pwsh ./Install-PackagedModule.ps1 -Scope AllUsers -Force
    Replace an AllUsers install at the same version (needs admin / sudo).
#>
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [switch]$Force,

    [string]$Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# 1. Detect supported PowerShell — fail fast if unsupported.
#    The module manifest declares PowerShellVersion = 7.4 and
#    CompatiblePSEditions = @('Core'); refuse anything else up front so the
#    user gets a clear, actionable error instead of an obscure load failure.
# ---------------------------------------------------------------------------

$MinVersion = [Version]'7.4'
$scriptName = $MyInvocation.MyCommand.Name

$edition = $PSVersionTable.PSEdition
if ($edition -ne 'Core') {
    throw @"
JwtDecoder requires PowerShell 7.4 or later (Core edition).
Detected: $edition $($PSVersionTable.PSVersion)

If you are running Windows PowerShell 5.1, install PowerShell 7+ from
https://aka.ms/powershell-release and then re-run this installer using
'pwsh' instead of 'powershell':

    pwsh ./$scriptName
"@
}

if ($PSVersionTable.PSVersion -lt $MinVersion) {
    throw @"
JwtDecoder requires PowerShell $MinVersion or later.
Detected: PowerShell $($PSVersionTable.PSVersion)

Upgrade PowerShell from https://aka.ms/powershell-release and try again.
"@
}

# ---------------------------------------------------------------------------
# 2. Locate the packaged module.
# ---------------------------------------------------------------------------

if (-not $Path) {
    $Path = Join-Path $PSScriptRoot 'Module'
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Packaged module folder not found at '$Path'. Did you extract the entire zip into one folder?"
}

$manifestPath = Join-Path $Path 'JwtDecoder.psd1'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Module manifest 'JwtDecoder.psd1' not found in '$Path'."
}

$manifest      = Test-ModuleManifest -Path $manifestPath
$moduleName    = $manifest.Name
$moduleVersion = $manifest.Version

Write-Host "PowerShell      : $($PSVersionTable.PSVersion) ($edition)"
Write-Host "Module package  : $moduleName $moduleVersion"
Write-Host "Source folder   : $Path"

# ---------------------------------------------------------------------------
# 3. Resolve the destination per scope.
# ---------------------------------------------------------------------------

if ($Scope -eq 'AllUsers') {
    if ($IsWindows) {
        $base = Join-Path $env:ProgramFiles 'PowerShell\Modules'
    } else {
        $base = '/usr/local/share/powershell/Modules'
    }
} else {
    if ($IsWindows) {
        $base = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
    } else {
        $base = Join-Path $HOME '.local/share/powershell/Modules'
    }
}

$target = Join-Path (Join-Path $base $moduleName) $moduleVersion

Write-Host "Target          : $target"
Write-Host "Scope           : $Scope"
Write-Host ""

if (Test-Path -LiteralPath $target) {
    if (-not $Force) {
        throw "Destination '$target' already exists. Re-run with -Force to overwrite."
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}

New-Item -ItemType Directory -Path $target -Force | Out-Null

# Copy the runtime files only. Skip PDBs (debugger symbols) to keep the
# install lean; everything PowerShell needs at runtime is preserved.
Get-ChildItem -LiteralPath $Path -File |
    Where-Object { $_.Extension -ne '.pdb' } |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $target $_.Name) -Force
    }

# ---------------------------------------------------------------------------
# 4. Verify the install and print a usage hint.
# ---------------------------------------------------------------------------

$installed = Test-ModuleManifest -Path (Join-Path $target 'JwtDecoder.psd1')

Write-Host "Installed:" -ForegroundColor Green
Write-Host "  Name    : $($installed.Name)"
Write-Host "  Version : $($installed.Version)"
Write-Host "  Path    : $target"
Write-Host "  Cmdlets : $($installed.ExportedCmdlets.Keys -join ', ')"
Write-Host ""

Write-Host "Discovered by PowerShell:"
Get-Module -ListAvailable -Name $moduleName | Format-Table Name, Version, Path
Write-Host ""

Write-Host "Try it:" -ForegroundColor Cyan
Write-Host "  Import-Module $moduleName"
Write-Host "  Get-Command -Module $moduleName"
Write-Host "  ConvertFrom-JsonWebToken '<your-jwt>'"
