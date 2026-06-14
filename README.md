# jwtdecode

Offline JSON Web Token decoder and (optional) signature verifier — shipped two ways:

- **`jwtdecode.exe`** — single ~2.4 MB native command-line executable (.NET 10 Native AOT, no runtime needed).
- **`JwtDecoder` PowerShell module** — binary module for PowerShell 7.4+ with two cmdlets.

Both share the same hardened decoding + verification core. Both are **100% offline.**

| | CLI exe | PowerShell module |
|---|---|---|
| Runtime needed | None (Native AOT) | PowerShell 7.4+ / .NET 8 |
| Single file | Yes (`jwtdecode.exe`) | DLL + manifest installed to PSModulePath |
| Output | Formatted text | Rich PSObject (`$jwt.Payload.sub` dot-access) |
| Pipeline-friendly | stdin | Yes (`Get-Content x.jwt \| ConvertFrom-JsonWebToken`) |
| Algorithms verified | HS/RS/PS/ES 256/384/512 | HS/RS/PS/ES 256/384/512 |

## Quick start — CLI

```powershell
# decode a token (positional argument)
jwtdecode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# read the token from a file
jwtdecode --file token.jwt

# pipe the token from stdin
Get-Content token.jwt | jwtdecode

# show everything, including raw base64 segments and signature bytes
jwtdecode --file token.jwt --detailed

# query a single claim (JSON form by default)
jwtdecode --file token.jwt --query payload.sub          # -> "1234567890"

# unwrap the string value with --raw
jwtdecode --file token.jwt --query payload.sub --raw    # -> 1234567890

# shorthand: bare names default to payload.<name>
jwtdecode --file token.jwt -q sub

# query multiple paths in one call (comma-separated)
jwtdecode --file token.jwt -q payload.sub,header.alg,payload.exp

# index into arrays and walk nested objects
jwtdecode --file token.jwt -q 'payload.roles[0],payload.address.city'

# verify the signature with a key file
jwtdecode --file token.jwt --verify --key-file hs256-secret.txt
jwtdecode --file token.jwt --verify --key-file rs256-public.pem

# pipe the key on stdin (token must come from --file or a positional argument)
type rs256-public.pem | jwtdecode --file token.jwt --verify --key-file -
```

## Quick start — PowerShell module

Build and install (offline; no PSGallery required):

```powershell
.\tools\Install-JwtDecoderModule.ps1 -Build
```

Then in any PowerShell session:

```powershell
Import-Module JwtDecoder

# Decode
$jwt = ConvertFrom-JsonWebToken $token
$jwt.Algorithm                # HS256
$jwt.Payload.sub              # 1234567890
$jwt.Expiration               # [DateTimeOffset]
$jwt | ConvertFrom-JsonWebToken -Detailed | Format-List

# Query a single claim by path (returns the typed .NET value)
Get-JsonWebTokenClaim $token -Name payload.sub          # 1234567890
Get-JsonWebTokenClaim $token -Name sub                  # shorthand for payload.sub
Get-JsonWebTokenClaim $token -Name header.alg           # HS256

# Multiple paths — pass an array or a comma-separated string
Get-JsonWebTokenClaim $token -Name payload.sub, payload.name, header.alg
Get-JsonWebTokenClaim $token -Name 'payload.roles[0]', 'payload.address.city'

# Verify — three parameter sets
Test-JsonWebTokenSignature -Token $token -KeyFile .\hs256-secret.txt
Test-JsonWebTokenSignature -Token $token -Secret (Read-Host -AsSecureString)
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem((Get-Content .\rsa-public.pem -Raw))
Test-JsonWebTokenSignature -Token $rsToken -PublicKey $rsa
```

## CLI reference

| Option              | Description                                                       |
| ------------------- | ----------------------------------------------------------------- |
| `<token>`           | Positional argument; the JWT to decode.                           |
| `--file <path>`     | Read the JWT from a file.                                         |
| (stdin)             | If neither positional nor `--file` is given, read from stdin.     |
| `-d`, `--detailed`  | Also print raw segments and signature bytes (hex).                |
| `-q`, `--query <p>` | Print only the value(s) at the given path(s). Comma-separated for multiple. |
| `--raw`             | With `--query`, unwrap string scalars (no JSON quotes).           |
| `--verify`          | Verify the signature. Requires `--key-file`.                      |
| `--key-file <path>` | Key file (HMAC raw secret or PEM-encoded RSA / EC PUBLIC key). Use `-` to read the key bytes from stdin (the token must then come from `--file` or a positional argument). |
| `-h`, `--help`      | Show help.                                                        |
| `-v`, `--version`   | Show version.                                                     |

### Query path syntax

| Path                       | Meaning                                                |
| -------------------------- | ------------------------------------------------------ |
| `payload.sub`              | The `sub` claim in the payload.                        |
| `header.alg`               | The `alg` parameter in the JOSE header.                |
| `sub`                      | Shorthand for `payload.sub` (bare names default to payload). |
| `payload.roles[0]`         | First element of the `roles` array.                    |
| `payload.address.city`     | Nested property walk.                                  |
| `payload."x5t#S256"`       | Use quoted segments for keys with non-identifier chars. |
| `payload`                  | The whole payload object.                              |
| `payload.sub,header.alg`   | Multiple paths in one call; one value per line.        |

Output is JSON-encoded by default — string values are emitted with their JSON quotes preserved and control characters left as `\uXXXX` escapes (terminal-injection-safe). Pass `--raw` to unwrap string scalars. Objects and arrays are always emitted as compact JSON. Missing paths exit with code `2`.

## PowerShell module reference

| Cmdlet | Purpose |
|---|---|
| `ConvertFrom-JsonWebToken [-Token] <string> [-Detailed]` | Decode a JWT to a `DecodedJsonWebToken`. Pipeline-friendly. |
| `ConvertFrom-JsonWebToken -Path <string> [-Detailed]` | Decode a JWT read from a file. |
| `Get-JsonWebTokenClaim [-Token] <string> -Name <string[]>` | Return the value(s) at one or more query paths as typed PowerShell objects. |
| `Get-JsonWebTokenClaim -Path <string> -Name <string[]>` | Same, reading the token from a file. |
| `Test-JsonWebTokenSignature -Token <string> -KeyFile <string>` | Verify using a key file (HMAC raw or PEM public). |
| `Test-JsonWebTokenSignature -Token <string> -Secret <SecureString>` | Verify HMAC using a SecureString secret. |
| `Test-JsonWebTokenSignature -Token <string> -PublicKey <RSA\|ECDsa>` | Verify using an already-loaded asymmetric public key. |

### Key file format

The format is inferred from the JWT's `alg` claim **and** cross-checked against the file content (this prevents the [algorithm-confusion attack](#security-notes)):

| Algorithm family | Key file contents                                              |
| ---------------- | -------------------------------------------------------------- |
| `HS256/384/512`  | Raw secret bytes. A single trailing `\n` or `\r\n` is stripped. **PEM-looking files are refused.** |
| `RS256/384/512`  | PEM-encoded RSA **public** key. Private keys are refused.      |
| `PS256/384/512`  | PEM-encoded RSA **public** key. Private keys are refused.      |
| `ES256/384/512`  | PEM-encoded EC **public** key; curve must match (`ES256↔P-256`, `ES384↔P-384`, `ES512↔P-521`). |

Size caps: token ≤ 1 MiB, key file ≤ 64 KiB, decoded JWT segment ≤ 256 KiB.

`Bearer ` prefixes and surrounding quotes are stripped automatically from the input token.

### Exit codes

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| 0    | Success.                                                             |
| 1    | Unexpected error.                                                    |
| 2    | Invalid input (bad token, bad arguments, missing/unreadable file).   |
| 3    | Signature verification failed.                                       |

## Build

Requires the .NET 10 SDK (CLI) and / or .NET 8 SDK (PS module). For the CLI's AOT publish also requires the MSVC C++ build tools.

```powershell
# Solution-wide build
dotnet build

# --- CLI ---
dotnet run --project src\JwtDecoder -- <token>           # iterate
dotnet publish src\JwtDecoder -c Release -r win-x64      # single exe
# -> src\JwtDecoder\bin\Release\net10.0\win-x64\publish\jwtdecode.exe

# --- PowerShell module ---
dotnet publish src\JwtDecoder.PowerShell -c Release      # module DLL + manifest
# -> src\JwtDecoder.PowerShell\bin\Release\net8.0\publish\

# Build + install in one step (offline; no PSGallery):
.\tools\Install-JwtDecoderModule.ps1 -Build              # CurrentUser scope
.\tools\Install-JwtDecoderModule.ps1 -Build -Scope AllUsers -Force
```

If `dotnet publish` for the CLI fails with `vswhere.exe is not recognized`, prepend the VS Installer directory to `PATH` for the session:

```powershell
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\Installer;" + $env:PATH
```

## Project layout

```
JwtDecoder.slnx
src\
    JwtDecoder.Core\               # net8.0 shared library, AOT-safe, zero NuGet deps
        Jwt.cs                     # JWT parsing (base64url, JSON, dup-key rejection, size caps)
        KeyMaterial.cs             # key wrapper with shared-vs-owned crypto provider semantics
        KeyLoader.cs               # PEM / raw-secret loading; algorithm-confusion + private-key guards
        Verifier.cs                # HMAC / RSA / ECDsa verification (curve+length checks)

    JwtDecoder\                    # net10.0 CLI exe, Native AOT, references Core
        Program.cs                 # entry, top-level error handling, exit codes, bounded I/O, forced GC
        Cli.cs                     # argument parsing + help text
        Output.cs                  # simplified + detailed formatters (terminal-escape safe)

    JwtDecoder.PowerShell\         # net8.0 binary module, references Core
        ConvertFromJsonWebTokenCommand.cs
        TestJsonWebTokenSignatureCommand.cs
        OutputTypes.cs             # DecodedJsonWebToken, JsonWebTokenVerification
        PsConversion.cs            # JsonElement -> PSObject (dot-access)
        JwtDecoder.psd1            # module manifest (PSGallery-ready)
        README.md                  # module-local docs

tools\
    Install-JwtDecoderModule.ps1   # offline install into PSModulePath

samples\
    generate-samples.ps1           # HS/RS/PS/ES happy-path test tokens + keys (pwsh 7)
    generate-attack-samples.ps1    # algorithm-confusion / wrong-curve / oversized / etc.
```

## JWKS workflow (network‑capable companion)

`jwtdecode` and the `JwtDecoder` PowerShell module are 100% offline. But cloud‑issued JWTs often have a public key you don't already have on disk — it lives at a JWKS endpoint, often discoverable via OIDC. To bridge that gap **without compromising the offline guarantee of the trusted binaries**, there's a separate companion:

| Component                                                       | Network capable? | How it ships |
|-----------------------------------------------------------------|---|---|
| `jwtdecode.exe` / `JwtDecoder` PowerShell module                | **No** (zero sockets — verified in CI) | as today |
| `jwksfetch.exe` / `JwtDecoder.Jwks` PowerShell module / `JwtDecoder.JwksFetcher` NuGet | **Yes** (HTTPS only, hardened) | **separate** binary / module / package |

The companion fetches one JWKS over HTTPS (or runs OIDC discovery), validates it strictly, picks the JWK matching the JWT's `kid`/`alg`/curve, and emits **one PEM block**. The trusted binary takes that PEM via stdin and verifies as usual.

### CLI pipeline

```powershell
# Direct JWKS URL
jwksfetch --jwks-url https://login.example.com/.well-known/jwks.json --token-file token.jwt |
  jwtdecode --file token.jwt --verify --key-file -

# Or via OIDC discovery (appends /.well-known/openid-configuration to the issuer)
jwksfetch --from-issuer https://login.example.com --token-file token.jwt |
  jwtdecode --file token.jwt --verify --key-file -

# File-based two-step (no TOCTOU on token.jwt between the two reads)
jwksfetch --jwks-url https://login.example.com/keys --token-file token.jwt > key.pem
jwtdecode --file token.jwt --verify --key-file key.pem
```

The pipe carries only a PEM public key. `jwtdecode.exe` opens no sockets and its binary contains no networking imports (verified at every CI run, see Security notes below).

### PowerShell pipeline

```powershell
Import-Module JwtDecoder       # offline (unchanged)
Import-Module JwtDecoder.Jwks  # network-capable (explicit opt-in)

# Explicit (deterministic Dispose)
$jwk = Get-JsonWebKey -Token $token -Issuer https://login.example.com
try {
    Test-JsonWebTokenSignature -Token $token -PublicKey $jwk.PublicKey
} finally { $jwk.Dispose() }

# Pipeline one-liner
Get-JsonWebKey -Token $token -JwksUri https://login.example.com/keys |
    Test-JsonWebTokenSignature -Token $token
```

### `jwksfetch` hardening (one set of guards per HTTPS hop)

- HTTPS only — no `--insecure` flag, ever. TLS 1.2 / 1.3 only; HTTP/3 not negotiated.
- SSRF deny‑list applied to every hop — IP literals AND DNS‑resolved addresses (IPv4‑mapped IPv6 unmapped first). Refused: loopback, link‑local (incl. `169.254.169.254` cloud metadata), 10/8, 172.16/12, 192.168/16, 0/8, 100.64/10; `::1`, `fc00::/7`, `fe80::/10`, `fec0::/10`, multicast; the literal hostname `localhost`.
- DNS rebinding defended via `SocketsHttpHandler.ConnectCallback` — we resolve, validate, then connect by `IPEndPoint` so the IP that survives validation is the IP TLS handshakes with. Skipped transparently when a proxy is in use (the proxy joins the trust chain).
- `UseProxy = false` by default. Ambient `HTTPS_PROXY` is ignored unless you pass `--use-system-proxy` or `--proxy <url>`.
- Bearer token is `byte[]`‑based and **stripped on every redirect**, even same‑host. For OIDC discovery the bearer is NOT sent on the discovery hop unless `--bearer-token-discovery` is given (opt‑in).
- Manual redirect loop with a cap (default 3, max 5); each hop is re‑validated against SSRF. Non‑HTTPS targets and same‑URL revisits refused.
- `AutomaticDecompression = None`; responses with `Content-Encoding` are refused.
- JWKS strictness: recursive duplicate‑key JSON rejection, `kty=oct` refused, any private component refused, `x5u`/`jku` refused, `x5c` ignored, `use=enc` refused, `key_ops` must contain `verify` if present, RSA modulus ≥ 2048 bits with odd exponent ≥ 3, EC `crv`/coordinate length bound by the JOSE binding.
- OIDC: issuer field MUST match the requested URL after canonicalization (lowercase host, default port stripped, single trailing slash stripped); same strict JSON path for both the metadata and the JWKS document.
- No on‑disk cache.
- Custom `--header-file` rejects dangerous header names (`Host`, `Authorization`, `Proxy-Authorization`, `Cookie`, `Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Expect`, `Content-Length`) and CR/LF/NUL in values.

### Trust boundary — read this twice

**The offline guarantee belongs to `jwtdecode.exe` alone, not to the pipeline.** When you pipe `jwksfetch | jwtdecode`, you've added a network‑capable process to your trust chain. The `jwksfetch` binary applies a defensible set of guards (above) — but it IS opening sockets. If your threat model strictly forbids any network activity in your verification path, **don't use the companion**; obtain the public key out of band and feed it to `jwtdecode --key-file <path>` directly. The same advice applies in PowerShell: the `JwtDecoder` module stays offline; importing `JwtDecoder.Jwks` loads `System.Net.Http` into the process for the session.

### See also

- `jwksfetch --help` for the full CLI surface.
- [`JwtDecoder.JwksFetcher` on nuget.org](https://www.nuget.org/packages/JwtDecoder.JwksFetcher) for embedding the JWKS pipeline in your own .NET app. Lock‑step exact‑pinned to `JwtDecoder.Core`.
- `src/JwtDecoder.JwksFetcher/README.md` (shipped with the nupkg) for the library‑level docs.
- `src/JwtDecoder.Jwks.PowerShell/README.md` for the cmdlet's deep dive.

## Offline guarantee — how it's enforced and how you can audit it

The offline promise of `jwtdecode` is **not** a claim made on a feature checklist. It is enforced by a layered scanner that runs in CI on every artifact-producing workflow (gating the upload), and that **you can run yourself** in under a minute against any binary you downloaded — with no need to trust our reading of the output.

### The promise (and its precise scope)

| In scope (offline-by-construction)        | Out of scope (network-capable by design) |
|-------------------------------------------|------------------------------------------|
| `jwtdecode.exe` (Native AOT CLI)          | `jwksfetch.exe`                          |
| `JwtDecoder` PowerShell module            | `JwtDecoder.Jwks` PowerShell module      |
| `JwtDecoder.Core` NuGet package           | `JwtDecoder.JwksFetcher` NuGet package    |

A normally-functioning binary in the **left** column cannot open a socket, resolve a hostname, or otherwise reach the network. Its only I/O channels are filesystem reads (token / key file), stdin (token bytes or PEM key bytes for `--key-file -`), stdout (decoded JSON / verification result), and stderr (errors / warnings). No DNS lookup. No HTTP. No proxy. No telemetry.

The **right** column carries all networking — pipe `jwksfetch | jwtdecode --key-file -` and the network trust boundary moves to whoever produced the PEM that `jwtdecode` reads from stdin.

### What the scanner checks — `tools/Verify-OfflineGuarantee.ps1`

Five independent checks. Four are pass/fail (`A`, `B`, `D`, `E`); any one failure aborts the workflow and the artifact never ships. The fifth (`C`) is informational only — explicitly documented as a heuristic so the strict signals stay credible.

| # | Layer | Tool | What it proves |
|--:|-------|------|----------------|
| **A** | Managed IL grep | `ilspycmd` 10.1.0.8386 (version-pinned for supply-chain hygiene) | No reference in `JwtDecoder.Core.dll` or the pre-AOT `jwtdecode.dll` to `[System.Net.Http]`, `[System.Net.Sockets]`, `[System.Net.WebSockets]`, `[System.Net.NetworkInformation]`, `[System.Net.Mail]`, `[System.Net.Primitives]`, `[System.Net.NameResolution]`, `[System.Net.Security]`, `[System.Net.Quic]`, `[System.Web*]`, `System.Net.WebClient`/`WebRequest`/`HttpWebRequest`/`Dns`, P/Invoke into `ws2_32` / `wininet` / `winhttp` / `urlmon` / `iphlpapi` / `dnsapi` / `libcurl` / `libssl` / `libssh2` / `nghttp2`, or reflective load attempts (`ldstr "System.Net.Http"`, `NativeLibrary::Load …ws2_32`, etc.). |
| **B** | Native AOT import inspection | `dumpbin /imports` (Windows), `objdump -p` + `objdump -T` (Linux), `otool -L` + `nm -u` (macOS) | The compiled AOT exe links no networking library (Windows DLL or *nix shared object) **and** imports no forbidden socket symbol (`socket`, `connect`, `getaddrinfo`, `gethostbyname`, `WSAStartup`, etc., including glibc `__GI_socket` aliases, Windows `__imp_socket@4` decorations, and glibc-versioned `socket@GLIBC_2.2.5` suffixes). On Unix, libc / libSystem cannot be library-deny-listed (they're universally NEEDED) so the symbol scan is the *only* signal — empty output or tool failure is **fail-closed**. |
| **C** | Raw-bytes string heuristic | PowerShell `-match` over the AOT exe bytes | Lists any networking type-name strings present anywhere in the binary. Explicitly marked **informational**: type-name strings often appear in BCL infrastructure that is not reachable from `jwtdecode`'s entrypoint. Layer-B is the authoritative signal for the AOT exe; Layer-C is shown for transparency only. |
| **D** | Transitive NuGet package check | `dotnet list package --include-transitive` | Neither `JwtDecoder.Core.csproj` nor `JwtDecoder.csproj` pulls a forbidden package (`System.Net.*`, `Microsoft.Extensions.Http`, `RestSharp`, `Flurl*`, etc.). Catches the supply-chain case where a future PR adds a dependency that itself transitively depends on networking. |
| **E** | Scan-vs-upload SHA-256 | PowerShell `Get-FileHash` | The exact binary the scanner inspected is the exact binary uploaded as the release artifact — bit-for-bit. Defends against any build step between scan and upload that could swap in a different binary. |

The IL dumps from layer **A** and the native imports listing from layer **B** are **uploaded as a transparency artifact** with every release, named `offline-guarantee-<rid>-Release-<sha>`. Download it from the workflow run page and re-grep it yourself — you don't have to trust our reading of the output.

Plus, every published AOT binary carries a Sigstore-backed [build-provenance attestation](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/attestations) — `gh attestation verify <file> --owner ShikeChen-MS` confirms the binary came from this repo's CI, signed by GitHub's OIDC identity for this workflow at this commit.

### How to audit a release yourself (≈ 1 minute)

You need three things, all open and stable:

1. The published `jwtdecode` binary for your platform — from the [GitHub Release](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/releases).
2. A clone of this repository at the tag matching that binary (for the verifier script).
3. The .NET SDK ≥ 10.0.x (only needed once, to install `ilspycmd`).

```powershell
# 1. Clone at the matching tag
git clone --depth 1 --branch <tag> https://github.com/ShikeChen-MS/JwtDecoder_local_cli.git
cd JwtDecoder_local_cli

# 2. Windows only: make `dumpbin` reachable. (Skip on Linux/macOS — objdump/nm
#    are pre-installed.) The simplest path is to run from a Developer
#    PowerShell for Visual Studio. Or, fully scripted:
$vsInstall = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
                -latest -property installationPath
$dumpbin = Get-ChildItem "$vsInstall\VC\Tools\MSVC" -Recurse -Filter dumpbin.exe |
           Where-Object { $_.FullName -match 'HostX64\\x64' } | Select-Object -First 1
$env:PATH = "$($dumpbin.Directory.FullName);$env:PATH"

# 3. Run the verifier. It auto-installs the pinned ilspycmd if needed.
pwsh -File tools/Verify-OfflineGuarantee.ps1 `
  -CoreDllPath        <path>\JwtDecoder.Core.dll `
  -ManagedCliDllPath  <path>\jwtdecode.dll `
  -AotExePath         <path>\jwtdecode.exe `
  -CoreProjectPath    src\JwtDecoder.Core\JwtDecoder.Core.csproj `
  -CliProjectPath     src\JwtDecoder\JwtDecoder.csproj
```

Expected verdict at the bottom of the output:

```
[A] Managed IL inspection (ilspycmd)
  PASS  JwtDecoder.Core IL contains no networking references.
  PASS  jwtdecode IL contains no networking references.

[B] Native AOT binary import inspection
  PASS  AOT binary links no forbidden native libraries.
  PASS  AOT binary imports no forbidden socket function names.

[C] Raw-bytes string heuristic (informational)
  WARN  AOT binary contains networking-type name strings (not necessarily reachable): …
  WARN  Layer-C is heuristic. Layer-B (native imports) is the authoritative signal.

[D] Transitive NuGet package check
  PASS  JwtDecoder.Core has no forbidden transitive packages.
  PASS  jwtdecode (CLI) has no forbidden transitive packages.

[E] Scan-vs-upload SHA-256 integrity
  PASS  Scan-vs-upload SHA-256 match (…).

OFFLINE GUARANTEE: PASS
```

The Layer-C `WARN` is normal — see the table above. The transparency artifacts (raw IL dump, raw native imports listing) are written to `ci-artifacts/disasm/` so you can re-grep them with your own tooling.

### Skim the IL yourself (the 30-second sanity check)

If you don't trust our deny-list, point `ilspycmd` at the binary and look for **anything** networking-related:

```powershell
dotnet tool install -g ilspycmd --version 10.1.0.8386
ilspycmd -il <path>\jwtdecode.dll | Select-String -Pattern 'System\.Net|pinvokeimpl|NativeLibrary::Load'
```

A clean run prints nothing. If you find a hit that isn't already on `$forbiddenIlPatterns` in `tools/Verify-OfflineGuarantee.ps1`, please file an issue — that means our deny-list is incomplete and the verifier could give false PASSes. **We want to know.**

### What this guarantee does NOT cover

- **`jwksfetch.exe`, the `JwtDecoder.Jwks` PowerShell module, and the `JwtDecoder.JwksFetcher` NuGet package are network-capable by design.** Importing the PS module into a session loads `System.Net.Http` into that session. The trust boundary is documented above ([Trust boundary — read this twice](#trust-boundary--read-this-twice)).
- **The verifier runs on the binary we built**, not on a binary an attacker substituted on disk. Combine it with the Sigstore attestation check above (`gh attestation verify …`) to close the substitution gap.
- **The verifier does not protect against runtime bugs** (parser errors, oversized-input handling, etc.). Those are unrelated security concerns — see the [Security notes](#security-notes) section below, and file bugs separately.

## Security notes

This tool is built for a no-compromise threat model: offline-only, security-first, drop-the-feature-if-it-weakens-anything.

**Network isolation**
- The `jwtdecode` process opens no sockets and resolves no hosts. See the dedicated [Offline guarantee](#offline-guarantee--how-its-enforced-and-how-you-can-audit-it) section above for exactly how this is enforced in CI and how you can audit it yourself.

**Algorithm-confusion guard (CVE-pattern: JWT alg=HS256 + RSA public key as MAC secret)**
- If the JWT's `alg` is `HS*` and the supplied key file *looks like PEM*, the tool refuses to verify and exits with code `2`. This blocks the well-known class of attacks where an attacker repurposes a published RSA/EC public key as an HMAC shared secret.

**Public-keys-only for asymmetric verification**
- PEM files containing any `PRIVATE KEY` label are refused. Verification only needs the public key — loading the private key would unnecessarily expose secret material.

**Strict algorithm/curve binding**
- The `alg` header is required to be a non-empty string.
- `alg: none` is always reported as INVALID with a security warning; exit code `3`.
- ECDSA curve is enforced: `ES256↔P-256`, `ES384↔P-384`, `ES512↔P-521`. Mismatch is refused.
- ECDSA signature length is enforced (`64`/`96`/`132` raw R‖S bytes — DER signatures are rejected).
- Duplicate top-level JOSE header / payload property names are rejected to prevent parser-differential ambiguity.

**Memory hygiene**
- HMAC secret bytes, decoded header/payload bytes, signature bytes, signing input, derived MAC bytes, and intermediate base64 buffers are all explicitly zeroed (`CryptographicOperations.ZeroMemory`) before release.
- PEM key data is read as `byte[]` and decoded into a mutable `char[]`; both buffers are zeroed after `ImportFromPem`. The PEM is never copied into an immutable `string`.
- HMAC newline-trimming copies into an exact-sized buffer instead of slicing — the original read buffer is zeroed; no residual secret data is left on the heap.
- `RSA` / `ECDsa` provider instances are disposed via `using` (releasing native key handles) inside a `try { } finally { }` so disposal runs even if verification throws.
- Constant-time comparison (`CryptographicOperations.FixedTimeEquals`) is used for HMAC verification.
- An aggressive compacting GC is forced before process exit (`GCCollectionMode.Aggressive`, blocking, compacting, twice, with LOH compaction) to reclaim any zeroed-but-still-reachable buffers.
- Caveat the tool cannot fix: tokens passed as a positional argument may persist in shell history / process listings. Prefer `--file` or stdin for sensitive tokens.

**DoS hardening**
- Token input (file or stdin) is capped at 1 MiB.
- Key file is capped at 64 KiB.
- Each decoded base64url segment is capped at 256 KiB before JSON parsing.
- JSON parsing uses default `MaxDepth = 64`, disallows comments, disallows trailing commas.

**Terminal-injection guard**
- String claim values are emitted using JSON-escape (`JsonElement.GetRawText()`), preserving `\u001b…` rather than emitting raw ESC bytes.
- Property names are scanned for ASCII / C1 control characters and re-escaped as `\uXXXX` before display.

**Out-of-range time claims**
- `iat`/`nbf`/`exp` values outside `DateTimeOffset` range are displayed as "out of representable range" and excluded from `EXPIRED`/`VALID` evaluation rather than crashing.

**Exit codes**
- Input validation, missing / oversized / unreadable files, unsupported algorithms → exit `2`.
- A well-formed key with a non-matching signature → exit `3`.
- Unexpected internal errors → exit `1` (no normal code path should reach this).
