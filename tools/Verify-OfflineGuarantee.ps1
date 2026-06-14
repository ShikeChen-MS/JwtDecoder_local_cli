<#
.SYNOPSIS
  Layered offline-guarantee verifier for jwtdecode and JwtDecoder.Core.

.DESCRIPTION
  Asserts that the offline trusted boundary is intact through several
  independent signals. ALL of A/B/D must pass; C is a heuristic warning.

  A. Managed IL inspection (ilspycmd)
       Disassembles JwtDecoder.Core.dll and the pre-AOT jwtdecode.dll
       and refuses any reference to networking namespaces, P/Invoke into
       networking native libraries, or reflective Assembly.Load /
       NativeLibrary.Load of networking modules.

  B. Native AOT binary import inspection (dumpbin / objdump / otool)
       Refuses any link-time dependency on a networking system library
       (WinHTTP, WS2_32, libcurl, libssl, nghttp2, ...).

  C. Raw-bytes string heuristic
       Greps the AOT exe for known networking type names. Logged as a
       warning - AOT trim may strip names even when code is linked, so
       this signal is informative, not authoritative.

  D. Transitive NuGet package check
       Runs `dotnet list package --include-transitive` on the offline
       projects and refuses any networking package (System.Net.*,
       Microsoft.Extensions.Http, RestSharp, Flurl*, ...).

  E. Optional scan-vs-upload integrity check
       If -UploadHashPath is given, compares its SHA-256 to that of
       -AotExePath to ensure the file inspected here is the same file
       that the publish workflow uploads.

  All managed-IL output is written to -DisasmOutDir for downstream
  upload as a transparency artifact.

.PARAMETER CoreDllPath
  Path to the published JwtDecoder.Core.dll managed assembly.

.PARAMETER ManagedCliDllPath
  Path to the pre-AOT jwtdecode.dll managed assembly (the IL form
  generated before native AOT compilation).

.PARAMETER AotExePath
  Path to the AOT-published jwtdecode (or jwtdecode.exe) binary.

.PARAMETER CoreProjectPath
  Path to JwtDecoder.Core.csproj for transitive package inspection.
  Defaults to the canonical location relative to the script.

.PARAMETER CliProjectPath
  Path to JwtDecoder.csproj for transitive package inspection.
  Defaults to the canonical location relative to the script.

.PARAMETER DisasmOutDir
  Directory where the disassembled IL bundle is written. Created if
  missing. Defaults to ./ci-artifacts/disasm.

.PARAMETER UploadHashPath
  Optional. If set, the script asserts SHA-256(-AotExePath) ==
  SHA-256(-UploadHashPath) so the file we inspected is byte-identical
  to the file the workflow uploads.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CoreDllPath,
    [Parameter(Mandatory)][string]$ManagedCliDllPath,
    [Parameter(Mandatory)][string]$AotExePath,
    [string]$CoreProjectPath,
    [string]$CliProjectPath,
    [string]$DisasmOutDir = './ci-artifacts/disasm',
    [string]$UploadHashPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve default project paths relative to the repo root.
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CoreProjectPath) { $CoreProjectPath = Join-Path $RepoRoot 'src/JwtDecoder.Core/JwtDecoder.Core.csproj' }
if (-not $CliProjectPath)  { $CliProjectPath  = Join-Path $RepoRoot 'src/JwtDecoder/JwtDecoder.csproj' }

foreach ($p in @($CoreDllPath, $ManagedCliDllPath, $AotExePath, $CoreProjectPath, $CliProjectPath)) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Error "Path not found: $p"
        exit 1
    }
}
New-Item -ItemType Directory -Force -Path $DisasmOutDir | Out-Null

$script:Fail = 0
function Fail([string]$Msg) {
    Write-Host "  FAIL  $Msg" -ForegroundColor Red
    $script:Fail++
}
function Pass([string]$Msg) {
    Write-Host "  PASS  $Msg" -ForegroundColor Green
}
function Warn([string]$Msg) {
    Write-Host "  WARN  $Msg" -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# A. Managed IL inspection
# -------------------------------------------------------------------

Write-Host "`n[A] Managed IL inspection (ilspycmd)" -ForegroundColor Cyan

if (-not (Get-Command ilspycmd -ErrorAction SilentlyContinue)) {
    Write-Host "  installing ilspycmd ..." -ForegroundColor DarkGray
    & dotnet tool install -g ilspycmd 2>&1 | Out-Null
    $toolsDir = if ($IsWindows) {
        Join-Path $env:USERPROFILE '.dotnet\tools'
    } else {
        Join-Path $env:HOME '.dotnet/tools'
    }
    if ((Test-Path $toolsDir) -and (-not ($env:PATH -split [System.IO.Path]::PathSeparator | Where-Object { $_ -eq $toolsDir }))) {
        $env:PATH = "$toolsDir$([System.IO.Path]::PathSeparator)$env:PATH"
    }
}

$forbiddenIlPatterns = @(
    # Direct assembly / namespace references in IL form ("[Assembly]Namespace.Type").
    '\[System\.Net\.Http',
    '\[System\.Net\.Sockets',
    '\[System\.Net\.WebSockets',
    '\[System\.Net\.NetworkInformation',
    '\[System\.Net\.Mail',
    '\[System\.Net\.Primitives',
    '\[System\.Net\.NameResolution',
    '\[System\.Web',
    'System\.Net\.WebClient',
    'System\.Net\.WebRequest',
    'System\.Net\.HttpWebRequest',
    'System\.Net\.Dns',
    # P/Invoke into networking libraries.
    'pinvokeimpl\("(ws2_32|wininet|winhttp|urlmon|iphlpapi|dnsapi|libcurl|libssl|libssh2|nghttp2)',
    # Reflective load attempts.
    'ldstr\s+"System\.Net\.Http"',
    'ldstr\s+"System\.Net\.Sockets"',
    'NativeLibrary::Load.*ws2_32',
    'NativeLibrary::Load.*libcurl'
)

function Test-ManagedAssembly {
    param([string]$DllPath, [string]$Label)
    $outFile = Join-Path $DisasmOutDir ("$Label.il")
    Write-Host "  disassembling $Label -> $outFile" -ForegroundColor DarkGray
    & ilspycmd -il $DllPath 2>&1 | Out-File -FilePath $outFile -Encoding utf8
    if (-not (Test-Path $outFile) -or (Get-Item $outFile).Length -eq 0) {
        Fail "$Label : ilspycmd produced no IL output."
        return
    }
    $content = Get-Content -LiteralPath $outFile -Raw
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($pat in $forbiddenIlPatterns) {
        $matchInfo = [regex]::Matches($content, $pat)
        if ($matchInfo.Count -gt 0) {
            $hits.Add("    ${pat}: $($matchInfo.Count) hit(s)") | Out-Null
        }
    }
    if ($hits.Count -gt 0) {
        Fail "$Label IL contains forbidden references:"
        foreach ($h in $hits) { Write-Host $h -ForegroundColor Red }
    } else {
        Pass "$Label IL contains no networking references."
    }
}

Test-ManagedAssembly -DllPath $CoreDllPath        -Label 'JwtDecoder.Core'
Test-ManagedAssembly -DllPath $ManagedCliDllPath  -Label 'jwtdecode'

# -------------------------------------------------------------------
# B. Native AOT binary import inspection
# -------------------------------------------------------------------

Write-Host "`n[B] Native AOT binary import inspection" -ForegroundColor Cyan

$forbiddenNativeLibs = @(
    'WINHTTP', 'WS2_32', 'WININET', 'URLMON',
    'IPHLPAPI', 'DNSAPI',
    'libcurl', 'libssl', 'libnghttp2', 'libssh2'
)

function Get-ImportsOutput {
    if ($IsWindows) {
        # dumpbin lives in the MSVC toolchain. AOT publish already requires it,
        # so we expect it to be reachable through vcvars / the developer prompt.
        $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
        if (-not $dumpbin) {
            return [pscustomobject]@{ Status = 'missing'; Tool = 'dumpbin'; Output = $null }
        }
        $out = & dumpbin /imports $AotExePath 2>&1
        return [pscustomobject]@{ Status = 'ok'; Tool = 'dumpbin'; Output = ($out | Out-String) }
    }
    elseif ($IsLinux) {
        $tool = Get-Command objdump -ErrorAction SilentlyContinue
        if (-not $tool) { return [pscustomobject]@{ Status = 'missing'; Tool = 'objdump'; Output = $null } }
        $out = & objdump -p $AotExePath 2>&1
        return [pscustomobject]@{ Status = 'ok'; Tool = 'objdump'; Output = ($out | Out-String) }
    }
    elseif ($IsMacOS) {
        $tool = Get-Command otool -ErrorAction SilentlyContinue
        if (-not $tool) { return [pscustomobject]@{ Status = 'missing'; Tool = 'otool'; Output = $null } }
        $out = & otool -L $AotExePath 2>&1
        return [pscustomobject]@{ Status = 'ok'; Tool = 'otool'; Output = ($out | Out-String) }
    }
    return [pscustomobject]@{ Status = 'unknown-os'; Tool = ''; Output = $null }
}

$importsInfo = Get-ImportsOutput
if ($importsInfo.Status -eq 'missing') {
    Fail "native imports tool '$($importsInfo.Tool)' is not on PATH; cannot inspect AOT binary."
}
elseif ($importsInfo.Status -ne 'ok') {
    Fail "unknown OS for native imports inspection: $($importsInfo.Status)"
}
else {
    $importsTxt = $importsInfo.Output
    # Save the imports listing as a transparency artifact alongside the IL.
    $importsArtifact = Join-Path $DisasmOutDir ("jwtdecode.aot.imports.$($importsInfo.Tool).txt")
    Set-Content -LiteralPath $importsArtifact -Value $importsTxt
    Write-Host "  saved $importsArtifact" -ForegroundColor DarkGray

    $bad = @()
    foreach ($lib in $forbiddenNativeLibs) {
        if ($importsTxt -match "(?i)$lib") { $bad += $lib }
    }
    if ($bad.Count -gt 0) {
        Fail "AOT binary links forbidden native libraries: $($bad -join ', ')"
    } else {
        Pass "AOT binary links no forbidden native libraries."
    }
}

# -------------------------------------------------------------------
# C. Raw-bytes string heuristic (warning only)
# -------------------------------------------------------------------

Write-Host "`n[C] Raw-bytes string heuristic (informational)" -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes($AotExePath)
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)
$heuristics = @('System.Net.Sockets', 'System.Net.Http', 'HttpClient', 'SocketsHttpHandler', 'TcpClient')
$found = @()
foreach ($h in $heuristics) {
    if ($text.Contains($h)) { $found += $h }
}
if ($found.Count -gt 0) {
    Warn "AOT binary contains networking-type name strings (not necessarily reachable): $($found -join ', ')"
    Warn "Layer-C is heuristic. Layer-B (native imports) is the authoritative signal."
} else {
    Pass "AOT binary contains no networking-type name strings."
}

# -------------------------------------------------------------------
# D. Transitive NuGet package check
# -------------------------------------------------------------------

Write-Host "`n[D] Transitive NuGet package check" -ForegroundColor Cyan

$forbiddenPackages = @(
    'System.Net.',
    'Microsoft.Extensions.Http',
    'RestSharp',
    'Flurl'
)

function Test-TransitivePackages {
    param([string]$ProjectPath, [string]$Label)
    $listOutput = & dotnet list $ProjectPath package --include-transitive 2>&1 | Out-String
    $bad = @()
    foreach ($prefix in $forbiddenPackages) {
        $regex = [regex]::Escape($prefix)
        $matches = [regex]::Matches($listOutput, "(?im)^\s*>?\s*$regex\S*")
        foreach ($m in $matches) {
            $line = $m.Value.Trim()
            if ($line) { $bad += "$Label : $line" }
        }
    }
    if ($bad.Count -gt 0) {
        Fail "$Label has forbidden transitive networking packages:"
        foreach ($b in $bad) { Write-Host "    $b" -ForegroundColor Red }
    } else {
        Pass "$Label has no forbidden transitive packages."
    }
}

Test-TransitivePackages -ProjectPath $CoreProjectPath -Label 'JwtDecoder.Core'
Test-TransitivePackages -ProjectPath $CliProjectPath  -Label 'jwtdecode (CLI)'

# -------------------------------------------------------------------
# E. Scan-vs-upload SHA-256 integrity (optional)
# -------------------------------------------------------------------

if ($UploadHashPath) {
    Write-Host "`n[E] Scan-vs-upload SHA-256 integrity" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $UploadHashPath)) {
        Fail "UploadHashPath not found: $UploadHashPath"
    } else {
        $scanned  = (Get-FileHash -LiteralPath $AotExePath -Algorithm SHA256).Hash
        $uploaded = (Get-FileHash -LiteralPath $UploadHashPath -Algorithm SHA256).Hash
        if ($scanned -ne $uploaded) {
            Fail "SHA-256 mismatch: scan='$scanned' upload='$uploaded'"
        } else {
            Pass "Scan-vs-upload SHA-256 match ($scanned)."
        }
    }
}

# -------------------------------------------------------------------
# Verdict
# -------------------------------------------------------------------

Write-Host ""
if ($script:Fail -gt 0) {
    Write-Host "OFFLINE GUARANTEE: FAIL ($script:Fail failure(s))" -ForegroundColor Red
    exit 1
} else {
    Write-Host "OFFLINE GUARANTEE: PASS" -ForegroundColor Green
    Write-Host "Transparency artifacts in $DisasmOutDir"
    exit 0
}
