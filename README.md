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
| `--key-file <path>` | Key file (HMAC raw secret or PEM-encoded RSA / EC PUBLIC key).    |
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

## Security notes

This tool is built for a no-compromise threat model: offline-only, security-first, drop-the-feature-if-it-weakens-anything.

**Network isolation**
- The process opens no sockets and resolves no hosts. Only filesystem reads (token / key file), stdin, stdout and stderr are used.

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
