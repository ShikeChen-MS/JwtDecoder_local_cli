param([string]$SamplesDir = "D:\JWTDecoder\samples")

Add-Type -AssemblyName System.Security

function To-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Make-Jwt {
    param([string]$Header, [string]$Payload, [scriptblock]$SignBytes)
    $h = To-Base64Url([Text.Encoding]::UTF8.GetBytes($Header))
    $p = To-Base64Url([Text.Encoding]::UTF8.GetBytes($Payload))
    $signingInput = [Text.Encoding]::ASCII.GetBytes("$h.$p")
    $sig = & $SignBytes $signingInput
    return "$h.$p." + (To-Base64Url $sig)
}

# 1) ALGORITHM CONFUSION: HMAC-sign using a PEM public key's BYTES as the HMAC secret.
$rsaPub = Get-Content -Raw -Encoding ascii (Join-Path $SamplesDir 'rs256-public.pem')
$pemBytes = [Text.Encoding]::ASCII.GetBytes($rsaPub.TrimEnd("`r","`n"))
$attackToken = Make-Jwt `
    -Header  '{"alg":"HS256","typ":"JWT"}' `
    -Payload '{"sub":"attacker","iat":1700000000}' `
    -SignBytes { param($msg) [System.Security.Cryptography.HMACSHA256]::HashData($pemBytes, $msg) }
$attackToken | Set-Content -Path (Join-Path $SamplesDir 'attack-alg-confusion.jwt') -NoNewline -Encoding ascii

# 2) PRIVATE KEY PEM: export the RSA private key so we can confirm it's REFUSED.
$rsaTemp = [System.Security.Cryptography.RSA]::Create(2048)
$rsaPrivPem = $rsaTemp.ExportPkcs8PrivateKeyPem()
$rsaPrivPem | Set-Content -Path (Join-Path $SamplesDir 'rsa-private.pem') -Encoding ascii
$privToken = Make-Jwt `
    -Header  '{"alg":"RS256","typ":"JWT"}' `
    -Payload '{"sub":"x","iat":1700000000}' `
    -SignBytes { param($msg) $rsaTemp.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
$privToken | Set-Content -Path (Join-Path $SamplesDir 'rs256-priv-signed.jwt') -NoNewline -Encoding ascii

# 3) WRONG CURVE: P-384 key but the JWT lies and claims ES256.
$ec384 = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP384)
$ec384Pub = $ec384.ExportSubjectPublicKeyInfoPem()
$ec384Pub | Set-Content -Path (Join-Path $SamplesDir 'es384-public.pem') -Encoding ascii
$wrongCurveToken = Make-Jwt `
    -Header  '{"alg":"ES256","typ":"JWT"}' `
    -Payload '{"sub":"wrong-curve","iat":1700000000}' `
    -SignBytes { param($msg) $ec384.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA384, [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation) }
$wrongCurveToken | Set-Content -Path (Join-Path $SamplesDir 'es256-wrong-curve.jwt') -NoNewline -Encoding ascii

# 4) DUPLICATE HEADER KEYS (alg appears twice).
$dupHeader = '{"alg":"HS256","alg":"none","typ":"JWT"}'
$dupPayload = '{"sub":"dup","iat":1700000000}'
$h64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($dupHeader))
$p64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($dupPayload))
$sigBytes = [System.Security.Cryptography.HMACSHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes("your-256-bit-secret"),
    [Text.Encoding]::ASCII.GetBytes("$h64.$p64"))
$s64 = To-Base64Url $sigBytes
"$h64.$p64.$s64" | Set-Content -Path (Join-Path $SamplesDir 'duplicate-alg.jwt') -NoNewline -Encoding ascii

# 5) TERMINAL ESCAPE INJECTION: claim value contains ESC[2J (clear screen).
$injHeader = '{"alg":"HS256","typ":"JWT"}'
$injPayload = '{"sub":"\u001b[2J\u001b[H[FAKE-VALID]","iat":1700000000}'
$h64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($injHeader))
$p64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($injPayload))
$sigBytes = [System.Security.Cryptography.HMACSHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes("your-256-bit-secret"),
    [Text.Encoding]::ASCII.GetBytes("$h64.$p64"))
$s64 = To-Base64Url $sigBytes
"$h64.$p64.$s64" | Set-Content -Path (Join-Path $SamplesDir 'terminal-injection.jwt') -NoNewline -Encoding ascii

# 6) OUT-OF-RANGE EXP.
$bigExpHeader  = '{"alg":"HS256","typ":"JWT"}'
$bigExpPayload = '{"sub":"big","iat":1700000000,"exp":9223372036854775807}'
$h64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($bigExpHeader))
$p64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($bigExpPayload))
$sigBytes = [System.Security.Cryptography.HMACSHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes("your-256-bit-secret"),
    [Text.Encoding]::ASCII.GetBytes("$h64.$p64"))
$s64 = To-Base64Url $sigBytes
"$h64.$p64.$s64" | Set-Content -Path (Join-Path $SamplesDir 'huge-exp.jwt') -NoNewline -Encoding ascii

# 7) OVERSIZED TOKEN — pad payload to > 1 MiB worth of base64.
$bigClaim = "x" * (1500000)  # 1.5M chars
$oversizePayload = ('{"sub":"big","note":"' + $bigClaim + '"}')
$h64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
$p64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($oversizePayload))
"$h64.$p64.abc" | Set-Content -Path (Join-Path $SamplesDir 'oversized.jwt') -NoNewline -Encoding ascii

# 8) ALG: NONE token (no signature).
$noneHeader = '{"alg":"none","typ":"JWT"}'
$nonePayload = '{"sub":"no-sig","iat":1700000000}'
$h64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($noneHeader))
$p64 = To-Base64Url([Text.Encoding]::UTF8.GetBytes($nonePayload))
"$h64.$p64." | Set-Content -Path (Join-Path $SamplesDir 'alg-none.jwt') -NoNewline -Encoding ascii

Write-Host "Generated security regression samples."
Get-ChildItem $SamplesDir -Filter '*.jwt' | Format-Table Name,Length
Get-ChildItem $SamplesDir -Filter '*.pem' | Format-Table Name,Length
