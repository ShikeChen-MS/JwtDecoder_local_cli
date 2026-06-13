@{
    # Identity
    RootModule        = 'JwtDecoder.PowerShell.dll'
    ModuleVersion     = '1.1.0'
    GUID              = '3d2a4eb1-adca-479b-9a7c-abdaa547f31b'
    Author            = 'JwtDecoder contributors'
    CompanyName       = 'JwtDecoder contributors'
    Copyright         = '(c) JwtDecoder contributors. All rights reserved.'
    Description       = 'Offline JSON Web Token decoder and signature verifier. Never makes network calls. Sensitive buffers are zeroed before release. Guards against the JWT algorithm-confusion attack. Cmdlets: ConvertFrom-JsonWebToken, Test-JsonWebTokenSignature, Get-JsonWebTokenClaim.'

    # PowerShell / runtime requirements
    PowerShellVersion      = '7.4'
    CompatiblePSEditions   = @('Core')
    DotNetFrameworkVersion = ''

    # Exports
    CmdletsToExport   = @(
        'ConvertFrom-JsonWebToken'
        'Test-JsonWebTokenSignature'
        'Get-JsonWebTokenClaim'
    )
    FunctionsToExport = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Files shipped with the module
    FileList = @(
        'JwtDecoder.PowerShell.dll'
        'JwtDecoder.Core.dll'
        'JwtDecoder.psd1'
        'README.md'
    )

    # PowerShell Gallery metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('JWT', 'JsonWebToken', 'Security', 'Crypto', 'Offline', 'HMAC', 'RSA', 'ECDsa')
            LicenseUri   = 'https://github.com/ShikeChen-MS/JwtDecoder_local_cli/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/ShikeChen-MS/JwtDecoder_local_cli'
            IconUri      = 'https://github.com/ShikeChen-MS.png'
            ReleaseNotes = @'
1.1.0
- New cmdlet Get-JsonWebTokenClaim for one-shot retrieval of specific claim(s) by query path.
- Path syntax: dot/bracket notation (e.g. payload.sub, header.alg, payload.roles[0]).
- Bare names default to payload.<name>; explicit header./payload. prefix overrides the scope.
- Quoted segments allow claim names containing dots or other special characters: payload."x5t#S256".

1.0.0
- Initial release.
- Cmdlets: ConvertFrom-JsonWebToken, Test-JsonWebTokenSignature.
- Supports HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.
- Algorithm-confusion guard (refuses PEM as HMAC secret).
- Private-key PEM refused for verification.
- Sensitive buffers zeroed on dispose.
- Fully offline; no network calls.
'@
            Prerelease   = ''
        }
    }
}
