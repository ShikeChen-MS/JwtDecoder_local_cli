<#
.SYNOPSIS
  Build (optional) and install the JwtDecoder PowerShell module into your PSModulePath.

.DESCRIPTION
  Copies the published JwtDecoder module (DLL + dependencies + manifest) into a versioned
  folder under your PSModulePath so PowerShell can auto-discover it via Import-Module.

  This is a fully OFFLINE install — no network calls, no PSGallery, no NuGet.

.PARAMETER Scope
  CurrentUser (default) installs to your per-user PSModulePath.
  AllUsers    installs to the machine-wide modules folder (requires Administrator).

.PARAMETER Build
  When set, runs `dotnet publish` for the module project before installing.

.PARAMETER Force
  Overwrite an existing install at the same version.

.EXAMPLE
  .\tools\Install-JwtDecoderModule.ps1 -Build
  # Builds, publishes, then installs into the current user's modules folder.

.EXAMPLE
  .\tools\Install-JwtDecoderModule.ps1 -Scope AllUsers -Force
  # Installs to the machine-wide modules folder, replacing any existing 1.0.0.
#>
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [switch]$Build,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Require PowerShell 7.4+ (matches the manifest).
if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw "JwtDecoder requires PowerShell 7.4 or later. Detected: $($PSVersionTable.PSVersion)."
}

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$ModuleProj = Join-Path $RepoRoot 'src\JwtDecoder.PowerShell\JwtDecoder.PowerShell.csproj'
$PublishDir = Join-Path $RepoRoot 'src\JwtDecoder.PowerShell\bin\Release\net8.0\publish'

if ($Build) {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "dotnet CLI not found. Install the .NET 8 (or later) SDK first."
    }
    Write-Host "Building JwtDecoder.PowerShell..." -ForegroundColor Cyan
    & dotnet publish $ModuleProj -c Release --nologo -v minimal
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)." }
}

if (-not (Test-Path $PublishDir)) {
    throw "Published module not found at '$PublishDir'. Run with -Build first, or run 'dotnet publish src\JwtDecoder.PowerShell -c Release' manually."
}

# Read the version from the manifest so the target folder name is correct.
$Manifest = Test-ModuleManifest -Path (Join-Path $PublishDir 'JwtDecoder.psd1')
$ModuleName    = $Manifest.Name
$ModuleVersion = $Manifest.Version

# Resolve the destination folder per scope.
if ($Scope -eq 'AllUsers') {
    if ($IsWindows) {
        $Base = Join-Path $env:ProgramFiles 'PowerShell\Modules'
    } else {
        $Base = '/usr/local/share/powershell/Modules'
    }
} else {
    # CurrentUser — match PSModulePath's user entry to avoid surprises.
    $UserEntries = $env:PSModulePath -split [System.IO.Path]::PathSeparator |
        Where-Object { $_ -and (Test-Path $_) -and ($_ -like "*$([Environment]::UserName)*" -or $_ -like "*$HOME*") }
    if ($UserEntries) {
        $Base = $UserEntries | Select-Object -First 1
    } elseif ($IsWindows) {
        $Base = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
    } else {
        $Base = Join-Path $HOME '.local/share/powershell/Modules'
    }
}

$TargetRoot = Join-Path $Base $ModuleName
$Target     = Join-Path $TargetRoot $ModuleVersion

Write-Host "Installing $ModuleName $ModuleVersion ($Scope) to:" -ForegroundColor Cyan
Write-Host "  $Target"

if (Test-Path $Target) {
    if (-not $Force) {
        throw "Destination '$Target' already exists. Re-run with -Force to overwrite."
    }
    Remove-Item $Target -Recurse -Force
}

New-Item -ItemType Directory -Path $Target -Force | Out-Null

# Copy only the files the module needs at runtime. Skip PDBs to keep the install lean.
Get-ChildItem $PublishDir -File |
    Where-Object { $_.Extension -ne '.pdb' } |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $Target $_.Name) -Force }

# Validate the installed manifest.
$Installed = Test-ModuleManifest -Path (Join-Path $Target 'JwtDecoder.psd1')
Write-Host ""
Write-Host "Installed:" -ForegroundColor Green
Write-Host "  Name      : $($Installed.Name)"
Write-Host "  Version   : $($Installed.Version)"
Write-Host "  Path      : $Target"
Write-Host "  Cmdlets   : $($Installed.ExportedCmdlets.Keys -join ', ')"

# Confirm PS can discover it.
Get-Module -ListAvailable -Name JwtDecoder | Format-Table Name, Version, Path

Write-Host ""
Write-Host "Try it:" -ForegroundColor Cyan
Write-Host "  Import-Module JwtDecoder"
Write-Host "  Get-Command -Module JwtDecoder"
Write-Host "  ConvertFrom-JsonWebToken <your-jwt>"
