# JwtDecoder.Core

[![NuGet](https://img.shields.io/nuget/v/JwtDecoder.Core.svg)](https://www.nuget.org/packages/JwtDecoder.Core)

Offline, hardened JSON Web Token decoding and signature verification for .NET 8+.

This is the shared core library that powers:

- **[`jwtdecode`](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/releases)** — single-file Native AOT CLI for Windows, Linux, and macOS.
- **[`JwtDecoder`](https://www.powershellgallery.com/packages/JwtDecoder/)** — PowerShell 7.4+ binary module.

## Why another JWT library?

Most JWT libraries try to cover the whole identity workflow — issuance, refresh, JWKS discovery, OIDC flows, key rotation. That's exactly the kind of code that grows attack surface faster than tests can cover it. `JwtDecoder.Core` does one thing only: it takes a compact JWS token and (optionally) a verification key, and tells you whether the signature checks out.

### Hardening properties

- **Offline by design** — never opens a socket. Filesystem reads are the only side-channel.
- **AOT-safe** — no reflection-based serialization, no dynamic code, zero NuGet dependencies. Works in `PublishAot` apps.
- **Algorithm-confusion guard** — refuses to verify an `HS*` token with a PEM-looking key file.
- **Private-key refusal** — PEM blocks labelled `PRIVATE KEY` are rejected; verification only needs the public key.
- **JOSE curve binding** — `ES256↔P-256`, `ES384↔P-384`, `ES512↔P-521`. Mismatched curves are refused.
- **Constant-time HMAC comparison** via `CryptographicOperations.FixedTimeEquals`.
- **DoS-bounded I/O** — token ≤ 1 MiB, key file ≤ 64 KiB, decoded segment ≤ 256 KiB, JSON `MaxDepth = 64`.
- **Memory hygiene** — secret bytes, decoded buffers, signing input, intermediate base64 / char arrays are all zeroed in `Dispose` / `finally`.
- **Strict parsing** — duplicate header/payload property names are rejected (parser-differential defense); `alg: none` always returns `Verified=false`.

## Install

```powershell
dotnet add package JwtDecoder.Core
```

## Usage

The `JwtTools` static class is the easiest entry point:

```csharp
using JwtDecoder.Core;

// Decode only (no signature check)
using var jwt = JwtTools.Decode(token);
Console.WriteLine(jwt.Algorithm);                          // e.g. "HS256"
Console.WriteLine(jwt.Payload.RootElement.GetProperty("sub").GetString());

// One-shot HMAC verification
var outcome = JwtTools.VerifyHmac(token, "your-256-bit-secret");
Console.WriteLine(outcome.Verified ? "OK" : $"Failed: {outcome.Error}");

// Decode + verify HMAC in one call (avoids double-parsing the token)
var (decoded, hmacResult) = JwtTools.DecodeAndVerifyHmac(token, secretBytes);
using (decoded)
{
    if (hmacResult.Verified)
    {
        var role = decoded.Payload.RootElement.GetProperty("role").GetString();
        // ...
    }
}

// RSA / RSA-PSS (RS256/384/512, PS256/384/512)
using var rsa = RSA.Create();
rsa.ImportFromPem(pemString);
var rsaResult = JwtTools.VerifyRsa(token, rsa);

// ECDsa (ES256/384/512)
using var ec = ECDsa.Create();
ec.ImportFromPem(pemString);
var ecResult = JwtTools.VerifyEcdsa(token, ec);

// File-based — same rules as the CLI (alg inferred + cross-checked against file)
var fileResult = JwtTools.VerifyWithKeyFile(token, "./hs256-secret.txt");
```

If you need more control (e.g. reusing an `RSA` across many verifications, owning the `KeyMaterial` lifetime, or accessing the raw signing input), drop down to the underlying `Jwt`, `JwtVerifier`, `KeyMaterial`, and `KeyLoader` types directly — `JwtTools` is just a thin convenience layer over them.

## Supported algorithms

| Family       | Algorithms                  | Key type accepted |
|--------------|-----------------------------|-------------------|
| HMAC         | HS256, HS384, HS512         | Raw secret bytes  |
| RSA-PKCS#1   | RS256, RS384, RS512         | RSA public key    |
| RSA-PSS      | PS256, PS384, PS512         | RSA public key    |
| ECDSA        | ES256, ES384, ES512         | EC public key (curve-bound) |

`alg: none` is parseable for inspection but always returns `Verified=false` with a clearly worded security warning in `VerifyOutcome.Error`.

## License

MIT — see [LICENSE](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/blob/master/LICENSE).
