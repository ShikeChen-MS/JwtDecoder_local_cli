<#
.SYNOPSIS
    Functional tests for the jwtdecode AOT binary, driven by the committed
    sample tokens and key files under samples/.

.DESCRIPTION
    Exercises the documented behaviour of jwtdecode:

      - Decode + verify for every supported algorithm family
        (HS256, RS256, PS256, ES256).
      - Time-status handling for expired and out-of-range exp claims.
      - Security hardening that the project is explicitly built around:
        algorithm-confusion guard, private-key refusal, JOSE curve
        binding, duplicate-header rejection, oversized-input rejection,
        terminal-injection guard, and alg=none handling.
      - Detailed output and stdin input paths.

    Each test asserts the documented exit code (0 success, 2 invalid
    input / refused, 3 signature verification failed) and, where useful,
    a substring (or absence of a forbidden byte) in the captured output.

    Designed to be invoked from the CI matrix once per platform and also
    runnable by a developer locally:

        pwsh ./tools/Test-AotBuild.ps1 `
            -BinPath src/JwtDecoder/bin/Release/net10.0/win-x64/publish/jwtdecode.exe

.PARAMETER BinPath
    Path to the published jwtdecode (or jwtdecode.exe) binary to test.

.PARAMETER SamplesDir
    Directory containing the sample JWTs and key files. Defaults to the
    repository's samples/ folder, resolved relative to this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinPath,
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

$script:bin     = (Resolve-Path -LiteralPath $BinPath).Path
$script:samples = (Resolve-Path -LiteralPath $SamplesDir).Path

Write-Host "Binary  : $script:bin"
Write-Host "Samples : $script:samples"

$script:passed   = 0
$script:failed   = 0
$script:failures = @()

function Sample([string]$name) { Join-Path $script:samples $name }

function Test-Case {
    param(
        [Parameter(Mandatory)][string]   $Name,
        [Parameter(Mandatory)][int]      $ExpectedExit,
                              [string[]] $Arguments           = @(),
                              [string]   $StdinFile,
                              [string[]] $MustContain         = @(),
                              [string[]] $MustNotContain      = @(),
                              [byte[]]   $MustNotContainBytes = @()
    )

    Write-Host ""
    Write-Host "[TEST] $Name"
    Write-Host "       args: $($Arguments -join ' ')"
    if ($StdinFile) { Write-Host "       stdin: $StdinFile" }

    # Run the binary, capturing stdout + stderr. $LASTEXITCODE comes from
    # the native command. We deliberately do not let pwsh swallow stderr.
    $output = $null
    try {
        if ($StdinFile) {
            $output = (Get-Content -Raw -LiteralPath $StdinFile | & $script:bin @Arguments 2>&1) | Out-String
        } else {
            $output = (& $script:bin @Arguments 2>&1) | Out-String
        }
    } catch {
        $output = $_.ToString()
    }
    $exit = $LASTEXITCODE

    $problems = New-Object System.Collections.Generic.List[string]
    if ($exit -ne $ExpectedExit) {
        $problems.Add("exit was $exit; expected $ExpectedExit")
    }
    foreach ($needle in $MustContain) {
        if ($output -notmatch [regex]::Escape($needle)) {
            $problems.Add("output missing substring '$needle'")
        }
    }
    foreach ($needle in $MustNotContain) {
        if ($output -match [regex]::Escape($needle)) {
            $problems.Add("output unexpectedly contained '$needle'")
        }
    }
    if ($MustNotContainBytes.Count -gt 0) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
        foreach ($b in $MustNotContainBytes) {
            if ($bytes -contains $b) {
                $problems.Add(("output contained forbidden byte 0x{0:X2}" -f $b))
            }
        }
    }

    if ($problems.Count -eq 0) {
        $script:passed++
        Write-Host "       PASS (exit $exit)"
    } else {
        $script:failed++
        $script:failures += $Name
        Write-Host "       FAIL (exit $exit)"
        foreach ($p in $problems) { Write-Host "         - $p" }
        Write-Host "       ---- captured output ----"
        Write-Host $output
        Write-Host "       ----        end       ----"
    }
}

# ---------------------------------------------------------------------------
# Trivial CLI plumbing
# ---------------------------------------------------------------------------

Test-Case -Name 'CLI: --version' `
    -Arguments @('--version') `
    -ExpectedExit 0 `
    -MustContain 'jwtdecode'

Test-Case -Name 'CLI: --help' `
    -Arguments @('--help') `
    -ExpectedExit 0 `
    -MustContain 'USAGE:', 'OPTIONS:', 'EXIT CODES:'

# ---------------------------------------------------------------------------
# Happy paths: decode + verify for each supported algorithm family
# ---------------------------------------------------------------------------

Test-Case -Name 'HS256: decode only' `
    -Arguments @('--file', (Sample 'hs256-token.jwt')) `
    -ExpectedExit 0 `
    -MustContain 'HS256', 'sub'

Test-Case -Name 'HS256: verify with the correct secret' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt')) `
    -ExpectedExit 0 `
    -MustContain 'matches the supplied key'

Test-Case -Name 'HS256: verify with the WRONG secret => exit 3' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-wrong.txt')) `
    -ExpectedExit 3 `
    -MustContain 'does NOT match'

Test-Case -Name 'RS256: verify with the RSA public key' `
    -Arguments @('--file', (Sample 'rs256-token.jwt'),
                 '--verify', '--key-file', (Sample 'rs256-public.pem')) `
    -ExpectedExit 0 `
    -MustContain 'RS256', 'matches the supplied key'

Test-Case -Name 'PS256 (RSA-PSS): verify with the same RSA public key' `
    -Arguments @('--file', (Sample 'ps256-token.jwt'),
                 '--verify', '--key-file', (Sample 'rs256-public.pem')) `
    -ExpectedExit 0 `
    -MustContain 'PS256', 'matches the supplied key'

Test-Case -Name 'ES256: verify with the P-256 public key' `
    -Arguments @('--file', (Sample 'es256-token.jwt'),
                 '--verify', '--key-file', (Sample 'es256-public.pem')) `
    -ExpectedExit 0 `
    -MustContain 'ES256', 'matches the supplied key'

# ---------------------------------------------------------------------------
# Time-status handling
# ---------------------------------------------------------------------------

Test-Case -Name 'Expired HS256 token: decoded but flagged EXPIRED' `
    -Arguments @('--file', (Sample 'expired-hs256.jwt')) `
    -ExpectedExit 0 `
    -MustContain 'EXPIRED'

Test-Case -Name 'Out-of-range exp (Int64.MaxValue): rendered safely, no crash' `
    -Arguments @('--file', (Sample 'huge-exp.jwt')) `
    -ExpectedExit 0 `
    -MustContain 'out of representable range'

# ---------------------------------------------------------------------------
# Security regressions
# ---------------------------------------------------------------------------

Test-Case -Name 'Algorithm-confusion: HS256 token + RSA public PEM => refused (exit 2)' `
    -Arguments @('--file', (Sample 'attack-alg-confusion.jwt'),
                 '--verify', '--key-file', (Sample 'rs256-public.pem')) `
    -ExpectedExit 2 `
    -MustContain 'algorithm-confusion'

Test-Case -Name 'Private-key PEM refused for verification (exit 2)' `
    -Arguments @('--file', (Sample 'rs256-priv-signed.jwt'),
                 '--verify', '--key-file', (Sample 'rsa-private.pem')) `
    -ExpectedExit 2 `
    -MustContain 'Refusing to load a private key'

Test-Case -Name 'Wrong-curve EC key (P-384 supplied for ES256) refused (exit 2)' `
    -Arguments @('--file', (Sample 'es256-wrong-curve.jwt'),
                 '--verify', '--key-file', (Sample 'es384-public.pem')) `
    -ExpectedExit 2 `
    -MustContain 'P-256', 'P-384'

Test-Case -Name 'Duplicate top-level header keys rejected as invalid JWT (exit 2)' `
    -Arguments @('--file', (Sample 'duplicate-alg.jwt')) `
    -ExpectedExit 2

Test-Case -Name 'Oversized token file (>1 MiB) refused (exit 2)' `
    -Arguments @('--file', (Sample 'oversized.jwt')) `
    -ExpectedExit 2 `
    -MustContain 'too large'

Test-Case -Name 'alg=none: decode-only succeeds and surfaces "none"' `
    -Arguments @('--file', (Sample 'alg-none.jwt')) `
    -ExpectedExit 0 `
    -MustContain 'none'

Test-Case -Name 'alg=none: --verify reports INVALID with security warning (exit 3)' `
    -Arguments @('--file', (Sample 'alg-none.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt')) `
    -ExpectedExit 3 `
    -MustContain 'does NOT match', 'red flag'

# A malicious claim value containing ESC (0x1B) must NOT appear as a raw
# escape byte in the captured output, even when the signature verifies.
Test-Case -Name 'Terminal-injection guard: ESC byte (0x1B) MUST NOT leak into output' `
    -Arguments @('--file', (Sample 'terminal-injection.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt')) `
    -ExpectedExit 0 `
    -MustNotContainBytes @([byte]0x1B)

# ---------------------------------------------------------------------------
# Detailed output and stdin input
# ---------------------------------------------------------------------------

Test-Case -Name 'Detailed output emits raw segments and signature bytes' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--detailed') `
    -ExpectedExit 0 `
    -MustContain 'header.segment', 'signature.bytes', 'signing.input'

Test-Case -Name 'Stdin input: token piped through Get-Content -Raw' `
    -StdinFile (Sample 'hs256-token.jwt') `
    -ExpectedExit 0 `
    -MustContain 'HS256'

# ---------------------------------------------------------------------------
# Query feature: happy path, multi-path, --raw, security guards
# ---------------------------------------------------------------------------

Test-Case -Name 'Query: --query payload.sub returns JSON-quoted value' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'payload.sub') `
    -ExpectedExit 0 `
    -MustContain '"1234567890"'

Test-Case -Name 'Query: --query sub shorthand resolves to payload.sub' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'sub') `
    -ExpectedExit 0 `
    -MustContain '"1234567890"'

Test-Case -Name 'Query: --query payload.sub --raw unwraps the value' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'payload.sub', '--raw') `
    -ExpectedExit 0 `
    -MustContain '1234567890' `
    -MustNotContain '"1234567890"'

Test-Case -Name 'Query: multi-path comma-separated emits one value per line' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'payload.sub,header.alg', '--raw') `
    -ExpectedExit 0 `
    -MustContain '1234567890', 'HS256'

Test-Case -Name 'Query: missing path returns exit 2 with descriptive stderr' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'payload.does_not_exist') `
    -ExpectedExit 2 `
    -MustContain 'not found'

# Security gate: --query mutually exclusive with --detailed (parser-level error).
Test-Case -Name 'Query: --query + --detailed combination refused (exit 2)' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--query', 'sub', '--detailed') `
    -ExpectedExit 2 `
    -MustContain 'cannot be combined'

# Security gate: --raw without --query refused (parser-level error).
Test-Case -Name 'Query: --raw without --query refused (exit 2)' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'), '--raw') `
    -ExpectedExit 2 `
    -MustContain '--raw is only meaningful with --query'

# Security: default --query output of a token with a deliberately-malicious ESC byte in a
# claim value MUST NOT leak the raw 0x1B byte to stdout/stderr. JSON encoding via
# Utf8JsonWriter must escape it.
Test-Case -Name 'Query (default): ESC byte in adversarial claim MUST stay JSON-escaped' `
    -Arguments @('--file', (Sample 'terminal-injection.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt'),
                 '--query', 'payload') `
    -ExpectedExit 0 `
    -MustNotContainBytes @([byte]0x1B)

# Security: --raw against a string claim containing a C0 / DEL / C1 control character
# must refuse with exit 2 and emit nothing on stdout (only a stderr diagnostic). This
# is the primary regression guard for terminal-injection via the --raw escape hatch.
# The 'sub' claim in terminal-injection.jwt contains literal ESC bytes (0x1B).
Test-Case -Name 'Query (--raw): refuses control-character string value (exit 2, no ESC on stdout)' `
    -Arguments @('--file', (Sample 'terminal-injection.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt'),
                 '--query', 'sub', '--raw') `
    -ExpectedExit 2 `
    -MustContain 'control character', 'terminal-control injection' `
    -MustNotContainBytes @([byte]0x1B)

# Security: --query + --verify with the WRONG key must emit ZERO query value on stdout.
# A consumer pipeline that ignores the exit code must not be able to consume claims from
# an unverified token. Only a stderr diagnostic is allowed, plus exit 3.
Test-Case -Name 'Query (--verify failed): no claim leaks to stdout, exit 3' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-wrong.txt'),
                 '--query', 'payload.sub') `
    -ExpectedExit 3 `
    -MustContain 'refusing to emit query output' `
    -MustNotContain '1234567890'

# Security: --query + --verify against an alg=none token must also suppress query output
# even though the parser accepts the token. This blocks the "pipe a sub claim from an
# unsigned token into a sensitive sink" pattern.
Test-Case -Name 'Query (--verify on alg=none): no claim leaks to stdout, exit 3' `
    -Arguments @('--file', (Sample 'alg-none.jwt'),
                 '--verify', '--key-file', (Sample 'hs256-secret.txt'),
                 '--query', 'sub') `
    -ExpectedExit 3 `
    -MustContain 'refusing to emit query output' `
    -MustNotContain 'no-sig'

# Atomic-commit invariant for multi-path queries: if any later path is missing, NO earlier
# value may be emitted on stdout. This protects scripts that ignore exit code from
# consuming partial data.
Test-Case -Name 'Query (multi-path): missing later path suppresses earlier values' `
    -Arguments @('--file', (Sample 'hs256-token.jwt'),
                 '--query', 'payload.sub,payload.does_not_exist') `
    -ExpectedExit 2 `
    -MustContain 'not found' `
    -MustNotContain '1234567890'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
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
