@{
    # Identity
    RootModule        = 'JwtDecoder.Jwks.PowerShell.dll'
    ModuleVersion     = '1.0.0'
    GUID              = '26b9f090-11c8-482d-a592-62d4ad3ac0db'
    Author            = 'JwtDecoder contributors'
    CompanyName       = 'JwtDecoder contributors'
    Copyright         = '(c) JwtDecoder contributors. All rights reserved.'
    Description       = 'JWKS acquisition (and OIDC discovery) companion to the JwtDecoder module. Network-capable: fetches a JWKS, validates it, selects the JWK matching a JWT''s kid/alg/crv, and returns the public key. The companion JwtDecoder module remains offline by construction.'

    # PowerShell / runtime requirements
    PowerShellVersion      = '7.4'
    CompatiblePSEditions   = @('Core')
    DotNetFrameworkVersion = ''

    # Exports (populated as cmdlets are added in Phase 5)
    CmdletsToExport   = @(
        'Get-JsonWebKey'
    )
    FunctionsToExport = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Files shipped with the module
    FileList = @(
        'JwtDecoder.Jwks.PowerShell.dll'
        'JwtDecoder.JwksFetcher.dll'
        'JwtDecoder.Core.dll'
        'JwtDecoder.Jwks.psd1'
        'README.md'
    )

    # PowerShell Gallery metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('JWT', 'JsonWebToken', 'JWKS', 'OIDC', 'OpenID', 'Security', 'Crypto')
            LicenseUri   = 'https://github.com/ShikeChen-MS/JwtDecoder_local_cli/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/ShikeChen-MS/JwtDecoder_local_cli'
            IconUri      = 'https://github.com/ShikeChen-MS.png'
            ReleaseNotes = @'
1.0.0
- Initial scaffold. Implementation pending.
'@
            Prerelease   = ''
        }
    }
}
