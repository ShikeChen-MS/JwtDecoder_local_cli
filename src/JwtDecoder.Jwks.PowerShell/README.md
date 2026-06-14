# JwtDecoder.Jwks PowerShell module

`Get-JsonWebKey` — fetch a JWKS (or run OIDC discovery), select the matching JWK
for a JWT, and return a typed object that pipes straight into the offline
`JwtDecoder` module's `Test-JsonWebTokenSignature`.

This is the **network‑capable** companion to the offline
[`JwtDecoder`](../JwtDecoder.PowerShell/README.md) module. The offline module's
trust posture is unchanged; importing this module is what brings networking into
the PowerShell process.

## Install

```powershell
# From source (offline; no PSGallery)
.\tools\Install-JwtDecoderJwksModule.ps1 -Build
```

## Quick start

```powershell
Import-Module JwtDecoder        # offline
Import-Module JwtDecoder.Jwks   # network-capable (explicit opt-in)

# Explicit form (deterministic Dispose)
$jwk = Get-JsonWebKey -Token $token -Issuer https://login.example.com
try {
    Test-JsonWebTokenSignature -Token $token -PublicKey $jwk.PublicKey
} finally { $jwk.Dispose() }

# Pipeline form — Test-JsonWebTokenSignature binds .PublicKey by property name
Get-JsonWebKey -Token $token -JwksUri https://login.example.com/keys |
    Test-JsonWebTokenSignature -Token $token
```

## `Get-JsonWebKey` parameters

Three parameter sets carry the key source — exactly one is required:

| Parameter | Notes |
|---|---|
| `-JwksUri <Uri>`     | Direct JWKS URL (HTTPS only). |
| `-Issuer <Uri>`      | OIDC discovery: appends `/.well-known/openid-configuration`. Refuses input that already contains a `/.well-known/` path. |
| `-JwksFile <path>`   | Local JWKS file (no network). |

Token source (mutually exclusive):

| Parameter | Notes |
|---|---|
| `-Token <string>`    | The JWT literal. |
| `-Path <string>`     | Read the JWT from a file. |

Network options (ignored for `-JwksFile`):

| Parameter | Notes |
|---|---|
| `-BearerTokenFile <path>`      | Sends `Authorization: Bearer <file>` on the JWKS request. **Stripped on every redirect.** |
| `-BearerTokenDiscovery`        | Opt‑in: also send the bearer to the OIDC discovery hop. Default is JWKS hop only. |
| `-HeaderFile <path>`           | Extra `Name: value` headers. Dangerous names (`Host`, `Authorization`, `Cookie`, `Connection`, `Transfer-Encoding`, …) refused by the parser. |
| `-CaBundle <path>`             | **Replaces** the system trust store with this PEM bundle. |
| `-TimeoutSeconds <int>`        | 1..60, default 10. |
| `-MaxResponseBytes <int>`      | Per‑hop body cap, default 256 KiB, max 1 MiB. |
| `-MaxRedirects <int>`          | 0..5, default 3. |
| `-RequireSameHostJwksUri`      | (Issuer set only) Refuses cross‑host `jwks_uri`. |

Proxy options (off by default — `HTTPS_PROXY` env var is ignored unless opted in):

| Parameter | Notes |
|---|---|
| `-Proxy <Uri>`                 | Explicit proxy URL. |
| `-UseSystemProxy`              | Honor `HTTPS_PROXY` / system proxy resolution. Mutually exclusive with `-Proxy`. |
| `-ProxyDefaultCredentials`     | Send OS default credentials (NTLM/Kerberos) to the proxy. |
| `-AllowPrivateProxy`           | Permit proxy URLs whose hostname resolves to private/loopback IPs (mitmproxy/Fiddler debug). |

## Returned object: `JsonWebKey`

| Property      | Type                          | Notes |
|---------------|-------------------------------|---|
| `Pem`         | `string`                      | SubjectPublicKeyInfo PEM block. |
| `Algorithm`   | `string`                      | JWK `alg`, or the JWT's `alg` if the JWK didn't carry one. |
| `Kty`         | `string`                      | `RSA` or `EC`. |
| `Kid`         | `string?`                     | Matched `kid`, if any. |
| `Crv`         | `string?`                     | EC curve when `Kty = EC`. |
| `SourceUri`   | `Uri?`                        | URL the JWKS was retrieved from; `$null` for `-JwksFile`. |
| `PublicKey`   | `RSA` or `ECDsa`              | Ready to feed into `Test-JsonWebTokenSignature -PublicKey`. |

`JsonWebKey` is `IDisposable` and owns its `PublicKey`. Wrap in a `try/finally`
when you call `Get-JsonWebKey` outside a pipeline; in the one‑liner pipeline
form, a finalizer releases the underlying `RSA`/`ECDsa` handle eventually.

## Security posture

Identical to the [`jwksfetch`](../JwksFetch/) CLI it shares a library with —
the same `JwtDecoder.JwksFetcher` library powers both. HTTPS only, TLS 1.2/1.3
pinned, no HTTP/3. SSRF deny‑list (IP literals + DNS‑resolved addresses with
IPv4‑mapped IPv6 unmapping). DNS rebinding defended via `ConnectCallback` (skipped
when a proxy is configured). Bearer token stays as `byte[]`, attached only to
the originally‑requested URL, stripped on every redirect. JWKS strictness: dup‑key
reject, `kty=oct` refused, private components refused, `x5u`/`jku` refused,
`x5c` ignored, RSA modulus ≥ 2048 bits, EC `crv` bound by JOSE.

See [`src/JwtDecoder.JwksFetcher/README.md`](../JwtDecoder.JwksFetcher/README.md)
for the full library‑level hardening summary.

## Air‑gapped environments

Importing this module loads `System.Net.Http` into the PowerShell process for
the **session's lifetime** — even after `Remove-Module JwtDecoder.Jwks`. If you
operate in an air‑gapped environment, don't import this module; keep using
`JwtDecoder` alone. The offline module's assembly references are unchanged
(only the `JwtDecoder.Core` dependency).

## License

MIT — see [LICENSE](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/blob/master/LICENSE).

