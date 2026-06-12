param([string]$OutDir = "D:\JWTDecoder\samples")

Add-Type -AssemblyName System.Security

function To-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Make-Jwt {
    param(
        [string]$Header,
        [string]$Payload,
        [scriptblock]$SignBytes  # takes byte[] message, returns byte[] signature
    )
    $h = To-Base64Url([Text.Encoding]::UTF8.GetBytes($Header))
    $p = To-Base64Url([Text.Encoding]::UTF8.GetBytes($Payload))
    $signingInput = [Text.Encoding]::ASCII.GetBytes("$h.$p")
    $sig = & $SignBytes $signingInput
    $s = To-Base64Url($sig)
    return "$h.$p.$s"
}

# ---- RS256 sample ----
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$rsaPubPem = $rsa.ExportSubjectPublicKeyInfoPem()
$rsaPubPem | Set-Content -Path (Join-Path $OutDir 'rs256-public.pem') -Encoding ascii

$rsaToken = Make-Jwt `
    -Header  '{"alg":"RS256","typ":"JWT","kid":"test-rsa"}' `
    -Payload '{"sub":"alice","iss":"https://example.com","aud":"my-app","iat":1700000000,"exp":4000000000,"scope":["read","write"]}' `
    -SignBytes { param($msg) $rsa.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
$rsaToken | Set-Content -Path (Join-Path $OutDir 'rs256-token.jwt') -NoNewline -Encoding ascii

# ---- PS256 sample (RSA-PSS) ----
$psToken = Make-Jwt `
    -Header  '{"alg":"PS256","typ":"JWT","kid":"test-rsa"}' `
    -Payload '{"sub":"alice-pss","iat":1700000000,"exp":4000000000}' `
    -SignBytes { param($msg) $rsa.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pss) }
$psToken | Set-Content -Path (Join-Path $OutDir 'ps256-token.jwt') -NoNewline -Encoding ascii

# ---- ES256 sample (NIST P-256, raw R||S) ----
$ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$ecPubPem = $ec.ExportSubjectPublicKeyInfoPem()
$ecPubPem | Set-Content -Path (Join-Path $OutDir 'es256-public.pem') -Encoding ascii

$ecToken = Make-Jwt `
    -Header  '{"alg":"ES256","typ":"JWT","kid":"test-ec"}' `
    -Payload '{"sub":"bob","iat":1700000000,"exp":4000000000,"role":"admin"}' `
    -SignBytes { param($msg) $ec.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation) }
$ecToken | Set-Content -Path (Join-Path $OutDir 'es256-token.jwt') -NoNewline -Encoding ascii

# ---- Expired HS256 sample ----
$hmacKey = [Text.Encoding]::UTF8.GetBytes("your-256-bit-secret")
$expToken = Make-Jwt `
    -Header  '{"alg":"HS256","typ":"JWT"}' `
    -Payload '{"sub":"old","iat":1500000000,"exp":1500000100}' `
    -SignBytes { param($msg) [System.Security.Cryptography.HMACSHA256]::HashData($hmacKey, $msg) }
$expToken | Set-Content -Path (Join-Path $OutDir 'expired-hs256.jwt') -NoNewline -Encoding ascii

Write-Host "Generated samples in $OutDir"
Get-ChildItem $OutDir | Format-Table Name,Length
