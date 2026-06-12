# JwtDecoder PowerShell Module

Offline JSON Web Token decoder + signature verifier as PowerShell 7.4+ cmdlets.

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `ConvertFrom-JsonWebToken` | Decode a JWT into a rich object with dot-accessible header/payload claims. |
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

## Security

- **No network access.** Pure local processing.
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
