# JwtDecoder.JwksFetcher

[![NuGet](https://img.shields.io/nuget/v/JwtDecoder.JwksFetcher.svg)](https://www.nuget.org/packages/JwtDecoder.JwksFetcher)

JWKS acquisition and OIDC discovery for [JwtDecoder.Core](https://www.nuget.org/packages/JwtDecoder.Core).
This is the **network‑capable** companion library: it fetches a JWKS (or
discovers one via OIDC), validates the contents strictly, selects the JWK
matching a given JWT, and emits the public key as PEM.

The trusted offline core (`JwtDecoder.Core`, `jwtdecode.exe`, the `JwtDecoder`
PowerShell module) stays exactly as it is. This package is the **only**
network‑capable JwtDecoder component.

## Install

```powershell
dotnet add package JwtDecoder.JwksFetcher
```

Pulls `JwtDecoder.Core` transitively at the exact same version (the two
packages release together and are pinned `[X.Y.Z]` against each other).

## Quick start

```csharp
using JwtDecoder.Core;
using JwtDecoder.JwksFetcher;

// 1. Parse the JWT once with Core's hardened parser to get kid/alg.
using var jwt = JwtTools.Decode(rawToken);
string? kid = jwt.Header.RootElement.TryGetProperty("kid", out var kidEl)
    && kidEl.ValueKind == System.Text.Json.JsonValueKind.String
    ? kidEl.GetString()
    : null;

// 2. Fetch the JWKS over HTTPS with strict hardening.
var opts = new FetcherOptions
{
    Timeout = TimeSpan.FromSeconds(10),
    MaxResponseBytes = 256 * 1024,
    MaxRedirects = 3,
    // Proxy off by default. Set ProxyMode.Explicit + ProxyUri (or System) to opt in.
};
FetchResult r = await JwksClient.FetchAsync(new Uri("https://login.example.com/.well-known/jwks.json"), opts);

// 3. Parse, select, emit PEM.
var keys = JwksDocument.Parse(r.Body);
var pick = JwkSelector.Select(keys, jwt.Algorithm, kid);
string pem = JwkToPem.ToPublicKeyPem(pick.Selected);

// 4. Verify with Core's KeyLoader + Verifier (or pipe the PEM into jwtdecode --key-file -).
using var key = KeyLoader.LoadFromBytes(System.Text.Encoding.UTF8.GetBytes(pem), jwt.Algorithm);
var outcome = JwtVerifier.Verify(jwt, key);
Console.WriteLine(outcome.Verified ? "OK" : $"Failed: {outcome.Error}");
```

For OIDC discovery, use `OidcDiscoveryClient.DiscoverAndFetchJwksAsync` instead —
it runs two HTTPS hops (`<issuer>/.well-known/openid-configuration` then
`jwks_uri`) with the same hardening per hop.

## Security posture

Every fetch goes through one set of guards:

- **HTTPS only.** No `--insecure`/no plaintext fallback. TLS 1.2/1.3 only;
  HTTP/3 is not negotiated.
- **SSRF deny‑list applied to every hop**, including IP literals AND DNS‑resolved
  addresses (IPv4‑mapped IPv6 is unmapped first). Refused: loopback, link‑local
  (incl. AWS/GCP metadata `169.254.169.254`), 10/8, 172.16/12, 192.168/16, 0/8,
  100.64/10 CGNAT; `::1`, `fc00::/7`, `fe80::/10`, `fec0::/10`, multicast, `::`;
  the literal hostname `localhost`.
- **DNS‑rebinding defence** via `SocketsHttpHandler.ConnectCallback`: we resolve,
  validate every address against the deny‑list, and connect by `IPEndPoint` so
  the IP that survives validation is the same IP TLS handshakes with. Skipped
  transparently when a proxy is in use (the proxy joins the trust chain).
- **`UseProxy = false`** by default; ambient `HTTPS_PROXY` is ignored unless
  callers opt in via `ProxyMode.System`.
- **`AutomaticDecompression = None`** — body cap can't be bypassed by a
  compression bomb. Responses with `Content-Encoding` are refused.
- **Manual redirect loop** with a cap (default 3, hard max 5); each hop is
  re‑validated against SSRF. Same‑URL revisits and non‑HTTPS targets are refused.
- **Bearer token is `byte[]`‑based** and **stripped on every redirect**, even
  same‑host.
- **JWKS strictness**: recursive duplicate‑key JSON rejection, `kty=oct`
  refused, any private component (`d`/`p`/`q`/`dp`/`dq`/`qi`) refused,
  `x5u`/`jku` refused (remote‑reference fields), `x5c` ignored, `use=enc`
  refused, `key_ops` must contain `verify` if present, RSA modulus ≥ 2048
  bits with odd exponent ≥ 3, EC `crv`/coordinate length bound by the JOSE
  binding (`P‑256`/`P‑384`/`P‑521`).
- **OIDC**: issuer field MUST match the requested URL after canonicalization
  (lowercase host, default 443 port stripped, single trailing slash stripped);
  metadata is parsed by the same strict JSON path as the JWKS document.
- **No on‑disk cache** in v1.
- **Memory hygiene**: response bodies, bearer tokens, header‑file bytes, and
  intermediate buffers are zeroed in `finally` blocks where reachable.

## Algorithm coverage

| Family | Algorithms | Selected JWK shape |
|---|---|---|
| RSA‑PKCS#1 | RS256, RS384, RS512 | `kty=RSA` with `n`, `e` |
| RSA‑PSS    | PS256, PS384, PS512 | `kty=RSA` with `n`, `e` |
| ECDSA      | ES256, ES384, ES512 | `kty=EC` with curve‑bound `crv`, `x`, `y` |

HMAC (`HS*`) is **not** a JWKS workflow — symmetric secrets never cross the
public‑key boundary. For HMAC, use `JwtDecoder.Core` directly.

## See also

- [JwtDecoder.Core](https://www.nuget.org/packages/JwtDecoder.Core) — offline
  decoder + verifier.
- The `jwksfetch` CLI and `JwtDecoder.Jwks` PowerShell module ship in the
  same repository and use this library directly.

## License

MIT — see [LICENSE](https://github.com/ShikeChen-MS/JwtDecoder_local_cli/blob/master/LICENSE).
