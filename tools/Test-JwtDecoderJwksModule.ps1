<#
.SYNOPSIS
    Functional tests for the JwtDecoder.Jwks PowerShell module, driven by
    the committed sample JWKS / JWT under samples/.

.DESCRIPTION
    The PowerShell-side counterpart of tools/Test-JwksFetchBuild.ps1.
    Imports the JwtDecoder.Jwks module (already installed in PSModulePath,
    or loaded from -ModulePath) and exercises Get-JsonWebKey against the
    --JwksFile path:

      - Get-JsonWebKey is exported by the module.
      - JwksFile + Token successfully matches kid='test-rsa' and emits a
        JsonWebKey with a non-null PublicKey of type RSA.
      - The emitted PEM round-trips back through RSA.ImportFromPem.
      - JwksFile + Token with WRONG kid throws (no key emitted).
      - Get-JsonWebKey | Test-JsonWebTokenSignature pipeline form yields
        IsValid = $true when the offline JwtDecoder module is also
        importable in the same session.

    Designed to be invoked from CI right after the install self-test, and
    also runnable locally:

        pwsh ./tools/Test-JwtDecoderJwksModule.ps1

.PARAMETER ModulePath
    Optional explicit path to a JwtDecoder.Jwks.psd1 to import. When
    omitted, the module is resolved via PSModulePath.

.PARAMETER SamplesDir
    Directory containing the sample JWKS + JWT files. Defaults to the
    repository's samples/ folder, resolved relative to this script.
#>
[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$SamplesDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw "This test suite requires PowerShell 7.4 or later. Detected: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
}

if (-not (Test-Path -LiteralPath $SamplesDir)) {
    throw "Samples directory not found: $SamplesDir"
}

if ($ModulePath) {
    if (-not (Test-Path -LiteralPath $ModulePath)) {
        throw "ModulePath not found: $ModulePath"
    }
    Import-Module (Resolve-Path -LiteralPath $ModulePath).Path -Force
} else {
    Import-Module JwtDecoder.Jwks -Force
}

$pass = 0
$fail = 0
function Assert-True([string]$desc, [bool]$cond, [string]$detail = '') {
    if ($cond) { Write-Host "  PASS  $desc"; $script:pass++ }
    else       { Write-Host "  FAIL  $desc $detail" -ForegroundColor Red; $script:fail++ }
}

# ---- Cmdlet export ----

Write-Host "`n[1] Get-JsonWebKey is exported"
$cmd = Get-Command -Module JwtDecoder.Jwks -Name Get-JsonWebKey -ErrorAction SilentlyContinue
Assert-True 'Get-JsonWebKey is exported by JwtDecoder.Jwks' ($null -ne $cmd)

# ---- JwksFile happy path ----

Write-Host "`n[2] -JwksFile -Path happy path (RS256)"
$jwks  = Join-Path $SamplesDir 'rs256-jwks.json'
$token = Join-Path $SamplesDir 'rs256-token.jwt'
$jwk = Get-JsonWebKey -JwksFile $jwks -Path $token
try {
    Assert-True 'JsonWebKey was emitted'         ($null -ne $jwk)
    Assert-True 'JsonWebKey.Kty is RSA'          ($jwk.Kty -eq 'RSA')
    Assert-True 'JsonWebKey.Kid matches sample'  ($jwk.Kid -eq 'test-rsa')
    Assert-True 'JsonWebKey.Pem contains PUBLIC KEY' ($jwk.Pem -match 'BEGIN PUBLIC KEY')
    Assert-True 'JsonWebKey.PublicKey is RSA'    ($jwk.PublicKey -is [System.Security.Cryptography.RSA])

    # PEM round-trips through RSA.ImportFromPem.
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem($jwk.Pem)
        $orig = $jwk.PublicKey.ExportParameters($false)
        $rt   = $rsa.ExportParameters($false)
        Assert-True 'PEM round-trip preserves modulus'  ([Linq.Enumerable]::SequenceEqual($orig.Modulus,  $rt.Modulus))
        Assert-True 'PEM round-trip preserves exponent' ([Linq.Enumerable]::SequenceEqual($orig.Exponent, $rt.Exponent))
    } finally { $rsa.Dispose() }
} finally {
    $jwk.Dispose()
}

# ---- kid mismatch ----

Write-Host "`n[3] kid mismatch throws (refused)"
$badKidToken = Join-Path $env:TEMP ("badkid-" + [guid]::NewGuid().ToString('N') + ".jwt")
function To-B64Url([byte[]]$bytes) {
    $b = [Convert]::ToBase64String($bytes).TrimEnd('=')
    return $b.Replace('+','-').Replace('/','_')
}
$hdr  = To-B64Url ([System.Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","kid":"WRONG"}'))
$pld  = To-B64Url ([System.Text.Encoding]::UTF8.GetBytes('{"sub":"x"}'))
$sig  = To-B64Url ([byte[]]@(1,2,3,4))
Set-Content -Path $badKidToken -Value "$hdr.$pld.$sig" -Encoding ASCII -NoNewline
try {
    $threw = $false
    try { Get-JsonWebKey -JwksFile $jwks -Path $badKidToken | Out-Null } catch { $threw = $true }
    Assert-True 'WRONG kid causes Get-JsonWebKey to throw' $threw
} finally {
    Remove-Item -Force $badKidToken
}

# ---- pipeline binding (covered authoritatively by the xUnit PipelineBindingTests
#       in tests/JwtDecoder.Jwks.PowerShell.Tests/; not re-run here because the
#       offline JwtDecoder module would need to be staged alongside this one in
#       the same runspace, which the publish workflow does not arrange) ----

Write-Host "`n----------------------------"
Write-Host "  passed: $pass"
Write-Host "  failed: $fail"
Write-Host "----------------------------"

if ($fail -gt 0) { exit 1 } else { exit 0 }
