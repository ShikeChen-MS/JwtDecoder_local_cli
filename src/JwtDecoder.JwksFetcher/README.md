# JwtDecoder.JwksFetcher

JWKS acquisition and OIDC discovery companion for [JwtDecoder.Core](../JwtDecoder.Core/README.md).

**This project is scaffolded but not yet implemented.** Implementation is tracked
in the JWKS companion design plan; see the repository root README for the
intended workflow once the library lands.

## Architectural intent

- Network-capable companion: fetches a JWKS (or discovers one via OIDC),
  validates it, selects the JWK matching a JWT's `kid`/`alg`/`crv`, and
  emits the public key as PEM.
- The trusted offline core (`JwtDecoder.Core`, `jwtdecode.exe`,
  `JwtDecoder` PowerShell module) stays exactly as it is. This package is
  the *only* network-capable JwtDecoder component.
- See [JwtDecoder.Core](../JwtDecoder.Core/README.md) for the offline
  decode/verify story.
