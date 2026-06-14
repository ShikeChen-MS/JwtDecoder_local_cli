# JwtDecoder PowerShell Module

Offline JSON Web Token decoder + signature verifier as PowerShell 7.4+ cmdlets.

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `ConvertFrom-JsonWebToken` | Decode a JWT into a rich object with dot-accessible header/payload claims. |
| `Get-JsonWebTokenClaim` | Return the value(s) at one or more query paths as typed PowerShell objects. |
| `Test-JsonWebTokenSignature` | Verify the signature against a `-KeyFile`, `-Secret <SecureString>`, or `-PublicKey <RSA|ECDsa>`. |

## Quick start

```powershell
Import-Module JwtDecoder

$token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

# Decode
$jwt = ConvertFrom-JsonWebToken $token
$jwt.Algorithm        # HS256
$jwt.Payload.sub      # 1234567890
$jwt.Payload.name     # John Doe

# Query specific claims directly (no intermediate object)
Get-JsonWebTokenClaim $token -Name payload.sub          # 1234567890
Get-JsonWebTokenClaim $token -Name sub                  # shorthand for payload.sub
Get-JsonWebTokenClaim $token -Name header.alg, payload.exp
Get-JsonWebTokenClaim $token -Name 'payload.roles[0]'
Get-JsonWebTokenClaim -Path .\token.jwt -Name payload.address.city

# Multi-name as comma-separated string also works
Get-JsonWebTokenClaim $token -Name 'payload.sub,header.alg'

# Verify with a file
Test-JsonWebTokenSignature -Token $token -KeyFile .\hs256-secret.txt

# Verify with a SecureString
$sec = ConvertTo-SecureString 'your-256-bit-secret' -AsPlainText -Force
Test-JsonWebTokenSignature -Token $token -Secret $sec

# Verify with an in-memory public key
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem((Get-Content .\rsa-public.pem -Raw))
Test-JsonWebTokenSignature -Token $rsToken -PublicKey $rsa

# Pipeline + detailed
Get-Content .\token.jwt -Raw | ConvertFrom-JsonWebToken -Detailed
```

## Query path syntax

Used by `Get-JsonWebTokenClaim -Name`. Same grammar as the CLI's `--query`:

| Path                       | Meaning                                                       |
| -------------------------- | ------------------------------------------------------------- |
| `payload.sub`              | The `sub` claim in the payload.                               |
| `header.alg`               | The `alg` parameter in the JOSE header.                       |
| `sub`                      | Shorthand for `payload.sub`.                                  |
| `payload.roles[0]`         | First element of the `roles` array.                           |
| `payload.address.city`     | Nested property walk.                                         |
| `payload."x5t#S256"`       | Quoted segment for keys with non-identifier characters.       |
| `payload`                  | The whole payload object (returned as a `PSObject`).          |

Returned values are typed: strings stay strings, numbers become `long` or `double`, booleans become `bool`, `null` becomes `$null`, JSON objects become `PSObject` (so you can keep using dot access), and arrays become `object[]`. A path that does not resolve emits a non-terminating `ItemNotFoundException` and produces no output for that path; other paths in the same call are still evaluated.

## Security

- **No network access.** Pure local processing. The module's only managed dependency is `JwtDecoder.Core`, which has no `System.Net.*` references. (If you also import the separate [`JwtDecoder.Jwks`](../JwtDecoder.Jwks.PowerShell/README.md) companion module into the same session, that module brings in `System.Net.Http` for JWKS acquisition; this offline module's assembly references remain unchanged.)
- **Algorithm-confusion guard.** `-Secret` and `-KeyFile` refuse PEM-shaped inputs when the JWT alg is HS\*.
- **Private-key PEMs are refused.** Verification only requires the public key.
- **ECDSA curve binding enforced.** `ES256↔P-256`, `ES384↔P-384`, `ES512↔P-521`. Mismatch is refused.
- **Sensitive buffers zeroed** via `CryptographicOperations.ZeroMemory` (HMAC secret, decoded segments, signing input, derived MAC, intermediate base64 buffers, SecureString-decoded bytes).
- **Size caps**: token ≤ 1 MiB, key file ≤ 64 KiB, each decoded segment ≤ 256 KiB.
- **Constant-time HMAC compare** (`CryptographicOperations.FixedTimeEquals`).
- **Duplicate JOSE header/payload property names rejected** (parser-differential guard).
- `Test-JsonWebTokenSignature` does NOT throw on signature mismatch — it returns `IsValid = $false`. Errors only when the input itself is invalid (bad token, missing/oversized key file, algorithm-confusion attempt, etc.).

## Caveats

- `PublicKey` instances are NOT disposed by the cmdlet — ownership stays with the caller.
- `SecureString` bytes briefly transit PS memory while being decoded to UTF-8 bytes. The intermediate buffer is zeroed; the SecureString itself stays encrypted in PS memory.
- PowerShell's garbage collector reclaims dead PSObjects asynchronously. For long-running sessions handling many tokens, call `[GC]::Collect()` if you want immediate reclamation.

See the top-level repo README for the full security analysis and threat model.
