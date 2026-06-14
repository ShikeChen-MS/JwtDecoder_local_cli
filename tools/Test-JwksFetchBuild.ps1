<#
.SYNOPSIS
    Functional tests for the jwksfetch AOT binary, driven by the committed
    sample JWKS / JWT under samples/.

.DESCRIPTION
    Exercises the documented behaviour of jwksfetch:

      - --help and --version succeed.
      - --jwks-file with a matching token emits one PEM on stdout, exit 0.
      - The emitted PEM, piped through jwtdecode --key-file -, verifies the
        original JWT (end-to-end pipeline).
      - --jwks-url with http:// is refused at runtime (HTTPS-only).
      - kid mismatch is exit 3 (logical refusal).
      - Two key sources are mutually exclusive (exit 2 from the argument parser).

    Designed to be invoked from the CI matrix once per platform and also
    runnable by a developer locally:

        pwsh ./tools/Test-JwksFetchBuild.ps1 `
            -BinPath src/JwksFetch/bin/Release/net10.0/win-x64/publish/jwksfetch.exe `
            -JwtDecodeBinPath src/JwtDecoder/bin/Release/net10.0/win-x64/publish/jwtdecode.exe

.PARAMETER BinPath
    Path to the published jwksfetch binary to test.

.PARAMETER JwtDecodeBinPath
    Path to the published jwtdecode binary used for the end-to-end pipeline
    assertion. Optional; if omitted, the pipeline-verify step is skipped.

.PARAMETER SamplesDir
    Directory containing the sample JWKS / JWT files. Defaults to the
    repository's samples/ folder, resolved relative to this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinPath,
    [string]$JwtDecodeBinPath,
    [string]$SamplesDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BinPath)) {
    Write-Error "Binary not found: $BinPath"
    exit 1
}
if (-not (Test-Path -LiteralPath $SamplesDir)) {
    Write-Error "Samples directory not found: $SamplesDir"
    exit 1
}

$Pass = 0
$Fail = 0

function Resolve-SamplePath([string]$Name) { return (Join-Path $SamplesDir $Name) }

function Assert-True([string]$Description, [bool]$Condition, [string]$Detail = '') {
    if ($Condition) {
        Write-Host "  PASS  $Description"
        $script:Pass++
    } else {
        Write-Host "  FAIL  $Description $Detail"
        $script:Fail++
    }
}

function Invoke-JwksFetch {
    param([string[]]$ArgList, [string]$StdinText = $null)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BinPath
    foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) | Out-Null }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $StdinText)
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $StdinText) {
        $p.StandardInput.Write($StdinText)
        $p.StandardInput.Close()
    }
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

# ---------- --help / --version ----------

Write-Host "`n[1] --help / --version exit 0"
$r = Invoke-JwksFetch @('--help')
Assert-True 'jwksfetch --help exits 0' ($r.ExitCode -eq 0)
Assert-True 'jwksfetch --help mentions usage' ($r.StdOut -match 'USAGE')

$r = Invoke-JwksFetch @('--version')
Assert-True 'jwksfetch --version exits 0' ($r.ExitCode -eq 0)
Assert-True 'jwksfetch --version prints binary name' ($r.StdOut -match 'jwksfetch')

# ---------- argument validation ----------

Write-Host "`n[2] argument validation"
$r = Invoke-JwksFetch @()
Assert-True 'no args -> exit 2' ($r.ExitCode -eq 2)

$r = Invoke-JwksFetch @('--jwks-url', 'https://example.com/k', '--jwks-file', 'k.json')
Assert-True 'two key sources -> exit 2' ($r.ExitCode -eq 2)

$r = Invoke-JwksFetch @('--bogus')
Assert-True 'unknown option -> exit 2' ($r.ExitCode -eq 2)

# ---------- --jwks-file happy path ----------

Write-Host "`n[3] --jwks-file happy path (RS256)"
$jwks  = Resolve-SamplePath 'rs256-jwks.json'
$token = Resolve-SamplePath 'rs256-token.jwt'
$r = Invoke-JwksFetch @('--jwks-file', $jwks, '--token-file', $token)
Assert-True 'jwks-file exits 0' ($r.ExitCode -eq 0)
Assert-True 'jwks-file emits one PEM' ($r.StdOut -match '-----BEGIN PUBLIC KEY-----')
Assert-True 'jwks-file emits end PEM' ($r.StdOut -match '-----END PUBLIC KEY-----')

# ---------- end-to-end pipeline if jwtdecode available ----------

if ($JwtDecodeBinPath -and (Test-Path -LiteralPath $JwtDecodeBinPath)) {
    Write-Host "`n[4] end-to-end pipeline: jwksfetch | jwtdecode --key-file -"
    $pem = $r.StdOut
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $JwtDecodeBinPath
    foreach ($a in @('--file', $token, '--verify', '--key-file', '-')) { $psi.ArgumentList.Add($a) | Out-Null }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p2 = [System.Diagnostics.Process]::Start($psi)
    $p2.StandardInput.Write($pem)
    $p2.StandardInput.Close()
    $jwtOut = $p2.StandardOutput.ReadToEnd()
    $jwtErr = $p2.StandardError.ReadToEnd()
    $p2.WaitForExit()
    Assert-True 'jwtdecode --key-file - exits 0' ($p2.ExitCode -eq 0) "stderr: $jwtErr"
    Assert-True 'jwtdecode reports VALID' ($jwtOut -match 'VALID')
} else {
    Write-Host "`n[4] pipeline assertion skipped (no -JwtDecodeBinPath)"
}

# ---------- HTTPS-only enforcement (no real network needed; CLI refuses scheme) ----------

Write-Host "`n[5] http:// jwks-url is refused at runtime"
$r = Invoke-JwksFetch @('--jwks-url', 'http://example.com/k', '--token-file', $token)
Assert-True 'http://: exit 2 or 4' ($r.ExitCode -eq 2 -or $r.ExitCode -eq 4)

# ---------- kid mismatch is exit 3 ----------

Write-Host "`n[6] kid mismatch -> exit 3"
# Synthesize a token with a kid that doesn't exist in samples/rs256-jwks.json.
function B64UrlAscii([string]$s) {
    $b = [System.Text.Encoding]::UTF8.GetBytes($s)
    return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$hdr  = B64UrlAscii '{"alg":"RS256","kid":"WRONG-kid"}'
$pld  = B64UrlAscii '{"sub":"x"}'
$junk = B64UrlAscii ([byte[]]@(1,2,3,4))
$badTokPath = Join-Path ([System.IO.Path]::GetTempPath()) ("badkid-" + [guid]::NewGuid().ToString('N') + ".jwt")
Set-Content -Path $badTokPath -Value "$hdr.$pld.$junk" -Encoding ASCII -NoNewline
try {
    $r = Invoke-JwksFetch @('--jwks-file', $jwks, '--token-file', $badTokPath)
    Assert-True 'kid mismatch -> exit 3' ($r.ExitCode -eq 3)
} finally {
    Remove-Item -Force $badTokPath
}

Write-Host "`n----------------------------"
Write-Host "  passed: $Pass"
Write-Host "  failed: $Fail"
Write-Host "----------------------------"

if ($Fail -gt 0) { exit 1 } else { exit 0 }
