# JwtDecoder.Jwks PowerShell module

Network-capable companion to the offline [JwtDecoder](../JwtDecoder.PowerShell/README.md) module.

**This module is scaffolded but not yet implemented.**

## Architectural intent

- Exports `Get-JsonWebKey` — fetches a JWKS (or discovers one via OIDC),
  selects the JWK matching a given JWT, and returns a typed `JsonWebKey`
  with a `.PublicKey` (RSA or ECDsa) ready to pipe into
  `Test-JsonWebTokenSignature`.
- This module loads `System.Net.Http` into the PowerShell process at
  `Import-Module` time. **The companion `JwtDecoder` module remains
  offline** — its assembly references do not change. Air-gapped
  environments should not import this module.

See the repository root README for the end-to-end JWKS workflow once the
implementation lands.
