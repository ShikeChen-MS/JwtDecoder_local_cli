<#
.SYNOPSIS
    Functional tests for the JwtDecoder PowerShell module, driven by the
    committed sample tokens and key files under samples/.

.DESCRIPTION
    The PowerShell-side counterpart of tools/Test-AotBuild.ps1. Imports
    the JwtDecoder module (already installed in PSModulePath, or loaded
    from -ModulePath) and exercises ConvertFrom-JsonWebToken and
    Test-JsonWebTokenSignature against every documented happy path AND
    every documented security regression:

      - Decode + verify per algorithm family (HS256, RS256, PS256, ES256).
      - Verify via -KeyFile, -Secret (SecureString), and -PublicKey
        (RSA / ECDsa instance) parameter sets.
      - Time-status handling (EXPIRED, out-of-range exp).
      - Security hardening: algorithm-confusion guard, private-key
        refusal, JOSE curve binding, duplicate-header rejection,
        oversized input rejection, alg=none reporting.
      - -Detailed populates the raw segment / signature fields.
      - Pipeline input (Get-Content -Raw | ConvertFrom-JsonWebToken).

    Designed to be invoked from CI right after the install self-test, and
    also runnable locally:

        pwsh ./tools/Test-JwtDecoderModule.ps1

.PARAMETER ModulePath
    Optional explicit path to a JwtDecoder.psd1 to import. When omitted
    the module is resolved via PSModulePath (i.e. the installed copy).

.PARAMETER SamplesDir
    Directory containing the sample JWTs and key files. Defaults to the
    repository's samples/ folder, resolved relative to this script.
#>
[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$SamplesDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Bootstrap: require PowerShell 7.4+, locate samples, import the module.
# ---------------------------------------------------------------------------

if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw "This test suite requires PowerShell 7.4 or later (Core edition). Detected: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
}

if (-not (Test-Path -LiteralPath $SamplesDir)) {
    throw "Samples directory not found: $SamplesDir"
}
$script:samples = (Resolve-Path -LiteralPath $SamplesDir).Path

if ($ModulePath) {
    if (-not (Test-Path -LiteralPath $ModulePath)) { throw "ModulePath not found: $ModulePath" }
    Import-Module -Name $ModulePath -Force
} else {
    Import-Module -Name JwtDecoder -Force
}

$mod = Get-Module -Name JwtDecoder
if (-not $mod) { throw "Failed to import JwtDecoder module." }

Write-Host "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Host "Module     : $($mod.Name) $($mod.Version)"
Write-Host "Source     : $($mod.Path)"
Write-Host "Samples    : $script:samples"
Write-Host ""

# ---------------------------------------------------------------------------
# Pass / fail tracking and a simple test runner.
# Each test scriptblock returns a list of failure reasons; an empty list
# means PASS. This keeps each assertion expressive without a heavyweight
# test framework.
# ---------------------------------------------------------------------------

$script:passed   = 0
$script:failed   = 0
$script:failures = @()

function Sample([string]$name) { Join-Path $script:samples $name }

function Read-TokenText([string]$file) {
    # The CLI passes tokens via --file / stdin; the PS cmdlet accepts
    # either -Path or -Token. For -Token tests we need the token string.
    (Get-Content -Raw -LiteralPath (Sample $file)).Trim()
}

function Assert-Test {
    param(
        [Parameter(Mandatory)][string]      $Name,
        [Parameter(Mandatory)][scriptblock] $Action
    )

    Write-Host "[TEST] $Name"
    $reasons = $null
    try {
        $reasons = & $Action
    } catch {
        $reasons = @("threw unexpected terminating error: $($_.Exception.Message)")
    }

    if ($null -eq $reasons) { $reasons = @() }
    elseif ($reasons -isnot [System.Collections.IEnumerable] -or $reasons -is [string]) {
        $reasons = @($reasons)
    }

    if ($reasons.Count -eq 0) {
        $script:passed++
        Write-Host "       PASS"
    } else {
        $script:failed++
        $script:failures += $Name
        Write-Host "       FAIL"
        foreach ($r in $reasons) { Write-Host "         - $r" }
    }
    Write-Host ""
}

# Helper: invoke a cmdlet expression and capture either its output or a
# terminating error message. Because the suite runs with $ErrorActionPreference
# = 'Stop', any WriteError raised by a cmdlet is promoted to a terminating
# exception inside the scriptblock — we catch it here so each test can assert
# on the message without aborting the whole run.
function Invoke-Capture {
    param([scriptblock]$Action)
    $caught = $null
    $result = $null
    try {
        $result = & $Action
    } catch {
        $caught = $_
    }
    [pscustomobject]@{
        Result        = $result
        ErrorRecord   = $caught
        ErrorMessage  = if ($caught) { $caught.Exception.Message } else { $null }
    }
}

# ---------------------------------------------------------------------------
# Module surface sanity
# ---------------------------------------------------------------------------

Assert-Test 'Module: ConvertFrom-JsonWebToken and Test-JsonWebTokenSignature are exported' {
    $issues = @()
    $exported = Get-Command -Module JwtDecoder | Select-Object -ExpandProperty Name
    foreach ($name in 'ConvertFrom-JsonWebToken', 'Test-JsonWebTokenSignature') {
        if ($exported -notcontains $name) { $issues += "cmdlet '$name' is not exported" }
    }
    $issues
}

# ---------------------------------------------------------------------------
# Decode happy paths
# ---------------------------------------------------------------------------

Assert-Test 'HS256: decode via -Path returns DecodedJsonWebToken' {
    $jwt = ConvertFrom-JsonWebToken -Path (Sample 'hs256-token.jwt')
    $issues = @()
    if (-not $jwt) { $issues += 'no result returned' }
    if ($jwt.Algorithm -ne 'HS256')       { $issues += "Algorithm='$($jwt.Algorithm)', expected HS256" }
    if ($jwt.Payload.sub -ne '1234567890') { $issues += "Payload.sub='$($jwt.Payload.sub)', expected '1234567890'" }
    if ($jwt.Payload.name -ne 'John Doe')  { $issues += "Payload.name='$($jwt.Payload.name)', expected 'John Doe'" }
    $issues
}

Assert-Test 'HS256: decode via pipeline (Get-Content -Raw | ConvertFrom-JsonWebToken)' {
    $jwt = Get-Content -Raw -LiteralPath (Sample 'hs256-token.jwt') | ConvertFrom-JsonWebToken
    $issues = @()
    if (-not $jwt -or $jwt.Algorithm -ne 'HS256') { $issues += 'pipeline decode did not return HS256 result' }
    $issues
}

Assert-Test '-Detailed populates HeaderSegment, PayloadSegment and SignatureHex' {
    $jwt = ConvertFrom-JsonWebToken -Path (Sample 'hs256-token.jwt') -Detailed
    $issues = @()
    if ([string]::IsNullOrEmpty($jwt.HeaderSegment))    { $issues += 'HeaderSegment was empty' }
    if ([string]::IsNullOrEmpty($jwt.PayloadSegment))   { $issues += 'PayloadSegment was empty' }
    if ([string]::IsNullOrEmpty($jwt.SignatureSegment)) { $issues += 'SignatureSegment was empty' }
    if ([string]::IsNullOrEmpty($jwt.SignatureHex))     { $issues += 'SignatureHex was empty' }
    elseif ($jwt.SignatureHex -notmatch '^[0-9a-f]+$')  { $issues += "SignatureHex '$($jwt.SignatureHex)' is not lowercase hex" }
    $issues
}

# ---------------------------------------------------------------------------
# Verify happy paths — exercise every -Key* parameter set
# ---------------------------------------------------------------------------

Assert-Test 'HS256: verify with -KeyFile (correct secret) => IsValid=$true' {
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'hs256-token.jwt') -KeyFile (Sample 'hs256-secret.txt')
    if (-not $r)              { return 'no verification result returned' }
    if (-not $r.IsValid)      { return "IsValid was $($r.IsValid); error: $($r.Error)" }
    if ($r.Algorithm -ne 'HS256') { return "Algorithm='$($r.Algorithm)', expected HS256" }
    @()
}

Assert-Test 'HS256: verify with -Secret (SecureString) => IsValid=$true' {
    $sec = ConvertTo-SecureString -String 'your-256-bit-secret' -AsPlainText -Force
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'hs256-token.jwt') -Secret $sec
    if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    @()
}

Assert-Test 'HS256: verify with WRONG -KeyFile => IsValid=$false (no exception)' {
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'hs256-token.jwt') -KeyFile (Sample 'hs256-wrong.txt')
    if (-not $r)        { return 'no verification result returned' }
    if ($r.IsValid)     { return 'expected IsValid=$false for a wrong secret' }
    if ([string]::IsNullOrEmpty($r.Error)) { return 'Error field was empty for an invalid signature' }
    @()
}

Assert-Test 'RS256: verify with -KeyFile (RSA public PEM)' {
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'rs256-token.jwt') -KeyFile (Sample 'rs256-public.pem')
    if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    if ($r.Algorithm -ne 'RS256')    { return "Algorithm='$($r.Algorithm)', expected RS256" }
    @()
}

Assert-Test 'RS256: verify with -PublicKey (pre-loaded RSA instance)' {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem((Get-Content -Raw -LiteralPath (Sample 'rs256-public.pem')))
        $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'rs256-token.jwt') -PublicKey $rsa
        if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    } finally { $rsa.Dispose() }
    @()
}

Assert-Test 'PS256 (RSA-PSS): verify with the same RSA public PEM' {
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'ps256-token.jwt') -KeyFile (Sample 'rs256-public.pem')
    if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    if ($r.Algorithm -ne 'PS256')    { return "Algorithm='$($r.Algorithm)', expected PS256" }
    @()
}

Assert-Test 'ES256: verify with -KeyFile (P-256 public PEM)' {
    $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'es256-token.jwt') -KeyFile (Sample 'es256-public.pem')
    if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    if ($r.Algorithm -ne 'ES256')    { return "Algorithm='$($r.Algorithm)', expected ES256" }
    @()
}

Assert-Test 'ES256: verify with -PublicKey (pre-loaded ECDsa instance)' {
    $ec = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $ec.ImportFromPem((Get-Content -Raw -LiteralPath (Sample 'es256-public.pem')))
        $r = Test-JsonWebTokenSignature -Token (Read-TokenText 'es256-token.jwt') -PublicKey $ec
        if (-not $r -or -not $r.IsValid) { return "IsValid=$($r.IsValid); error: $($r.Error)" }
    } finally { $ec.Dispose() }
    @()
}

# ---------------------------------------------------------------------------
# Time-status handling
# ---------------------------------------------------------------------------

Assert-Test 'Expired HS256: TimeStatus=EXPIRED' {
    $jwt = ConvertFrom-JsonWebToken -Path (Sample 'expired-hs256.jwt')
    if ($jwt.TimeStatus -ne 'EXPIRED') { return "TimeStatus='$($jwt.TimeStatus)', expected EXPIRED" }
    @()
}

Assert-Test 'Out-of-range exp: Expiration is $null (not thrown, not crashed)' {
    $jwt = ConvertFrom-JsonWebToken -Path (Sample 'huge-exp.jwt')
    if ($null -ne $jwt.Expiration) { return "Expiration was '$($jwt.Expiration)', expected null for out-of-range value" }
    @()
}

# ---------------------------------------------------------------------------
# Security regressions — each must surface an ErrorRecord (non-terminating)
# and must NOT return a JsonWebTokenVerification with IsValid=$true.
# ---------------------------------------------------------------------------

Assert-Test 'Algorithm-confusion: HS256 token + RSA public PEM => error, no result' {
    $r = Invoke-Capture {
        Test-JsonWebTokenSignature `
            -Token (Read-TokenText 'attack-alg-confusion.jwt') `
            -KeyFile (Sample 'rs256-public.pem')
    }
    $issues = @()
    if ($r.Result)             { $issues += "expected no result, but got IsValid=$($r.Result.IsValid)" }
    if (-not $r.ErrorRecord)   { $issues += 'no error was raised' }
    elseif ($r.ErrorMessage -notmatch 'algorithm-confusion') {
        $issues += "error did not mention 'algorithm-confusion': $($r.ErrorMessage)"
    }
    $issues
}

Assert-Test 'Private-key PEM refused for verification => error' {
    $r = Invoke-Capture {
        Test-JsonWebTokenSignature `
            -Token (Read-TokenText 'rs256-priv-signed.jwt') `
            -KeyFile (Sample 'rsa-private.pem')
    }
    $issues = @()
    if ($r.Result)             { $issues += "expected no result, but got IsValid=$($r.Result.IsValid)" }
    if (-not $r.ErrorRecord)   { $issues += 'no error was raised' }
    elseif ($r.ErrorMessage -notmatch 'private key') {
        $issues += "error did not mention 'private key': $($r.ErrorMessage)"
    }
    $issues
}

Assert-Test 'Wrong-curve EC key (P-384 supplied for ES256) => error' {
    $r = Invoke-Capture {
        Test-JsonWebTokenSignature `
            -Token (Read-TokenText 'es256-wrong-curve.jwt') `
            -KeyFile (Sample 'es384-public.pem')
    }
    $issues = @()
    if ($r.Result)             { $issues += "expected no result, but got IsValid=$($r.Result.IsValid)" }
    if (-not $r.ErrorRecord)   { $issues += 'no error was raised' }
    elseif ($r.ErrorMessage -notmatch 'P-256.*P-384|P-384.*P-256') {
        $issues += "error did not mention the curve mismatch: $($r.ErrorMessage)"
    }
    $issues
}

Assert-Test 'Duplicate top-level header keys rejected => error, no result' {
    $r = Invoke-Capture { ConvertFrom-JsonWebToken -Path (Sample 'duplicate-alg.jwt') }
    $issues = @()
    if ($r.Result)             { $issues += 'expected no result for a duplicate-key JWT' }
    if (-not $r.ErrorRecord)   { $issues += 'no error was raised' }
    elseif ($r.ErrorMessage -notmatch 'duplicate') {
        $issues += "error did not mention 'duplicate': $($r.ErrorMessage)"
    }
    $issues
}

Assert-Test 'Oversized token file (>1 MiB) refused => error' {
    $r = Invoke-Capture { ConvertFrom-JsonWebToken -Path (Sample 'oversized.jwt') }
    $issues = @()
    if ($r.Result)             { $issues += 'expected no result for an oversized token' }
    if (-not $r.ErrorRecord)   { $issues += 'no error was raised' }
    elseif ($r.ErrorMessage -notmatch 'too large|max ') {
        $issues += "error did not mention the size limit: $($r.ErrorMessage)"
    }
    $issues
}

# ---------------------------------------------------------------------------
# alg=none handling
# ---------------------------------------------------------------------------

Assert-Test 'alg=none: decode-only succeeds and surfaces Algorithm=none' {
    $jwt = ConvertFrom-JsonWebToken -Path (Sample 'alg-none.jwt')
    if (-not $jwt)               { return 'no result returned' }
    if ($jwt.Algorithm -ne 'none') { return "Algorithm='$($jwt.Algorithm)', expected 'none'" }
    @()
}

Assert-Test 'alg=none: verify is rejected (cmdlet refuses to load a key for an unsupported alg)' {
    # The PowerShell cmdlet refuses verification of alg=none up front via
    # KeyLoader.Load, which throws NotSupportedException for any alg not in
    # the HS*/RS*/PS*/ES* set. This is a stricter (and equally safe) stance
    # than the CLI, which special-cases alg=none and lets the verifier
    # return a "red flag" outcome. Either way the security-critical
    # invariant holds: alg=none must never produce IsValid=$true.
    $r = Invoke-Capture {
        Test-JsonWebTokenSignature -Token (Read-TokenText 'alg-none.jwt') -KeyFile (Sample 'hs256-secret.txt')
    }
    $issues = @()
    if ($r.Result -and $r.Result.IsValid) { $issues += 'alg=none unexpectedly produced IsValid=$true' }
    if (-not $r.ErrorRecord)              { $issues += 'no error was raised for alg=none verify' }
    elseif ($r.ErrorMessage -notmatch "not supported for algorithm 'none'") {
        $issues += "error did not mention 'not supported for algorithm none': $($r.ErrorMessage)"
    }
    $issues
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host "==========================================="
Write-Host "Passed : $script:passed"
Write-Host "Failed : $script:failed"
if ($script:failed -gt 0) {
    Write-Host "Failing tests:"
    foreach ($f in $script:failures) { Write-Host "  - $f" }
    Write-Host "==========================================="
    exit 1
}
Write-Host "All $script:passed tests passed."
Write-Host "==========================================="
exit 0
