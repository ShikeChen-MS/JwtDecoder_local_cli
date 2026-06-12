using System.Security.Cryptography;

namespace JwtDecoder.Core;

public sealed record VerifyOutcome(bool Verified, string Algorithm, string? Error);

public static class JwtVerifier
{
    /// <summary>
    /// Verify a JWT's signature against the supplied key material.
    /// Returns a <see cref="VerifyOutcome"/> instead of throwing for cryptographic failures.
    /// </summary>
    public static VerifyOutcome Verify(Jwt jwt, KeyMaterial? key)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        string alg = jwt.Algorithm;

        if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            return new VerifyOutcome(false, alg, "Algorithm is 'none' — there is no signature to verify. This is a security red flag.");

        if (key is null)
            return new VerifyOutcome(false, alg, "No key material was supplied.");

        if (jwt.SignatureBytes.Length == 0)
            return new VerifyOutcome(false, alg, "Signature segment is empty.");

        try
        {
            bool ok = alg switch
            {
                "HS256" => VerifyHmac(jwt, key, HashAlgorithmName.SHA256),
                "HS384" => VerifyHmac(jwt, key, HashAlgorithmName.SHA384),
                "HS512" => VerifyHmac(jwt, key, HashAlgorithmName.SHA512),

                "RS256" => VerifyRsa(jwt, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "RS384" => VerifyRsa(jwt, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
                "RS512" => VerifyRsa(jwt, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),

                "PS256" => VerifyRsa(jwt, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                "PS384" => VerifyRsa(jwt, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
                "PS512" => VerifyRsa(jwt, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),

                "ES256" => VerifyEcdsa(jwt, key, HashAlgorithmName.SHA256, expectedSig: 64,  expectedKeySize: 256),
                "ES384" => VerifyEcdsa(jwt, key, HashAlgorithmName.SHA384, expectedSig: 96,  expectedKeySize: 384),
                "ES512" => VerifyEcdsa(jwt, key, HashAlgorithmName.SHA512, expectedSig: 132, expectedKeySize: 521),

                _ => throw new NotSupportedException(
                    $"Algorithm '{alg}' is not supported. Supported: HS/RS/PS/ES with 256, 384, 512."),
            };
            return new VerifyOutcome(ok, alg, ok ? null : "Signature does not match.");
        }
        catch (Exception ex)
        {
            return new VerifyOutcome(false, alg, ex.Message);
        }
    }

    private static bool VerifyHmac(Jwt jwt, KeyMaterial key, HashAlgorithmName hash)
    {
        if (key.Kind != KeyKind.Hmac || key.HmacBytes is null)
            throw new InvalidOperationException("Algorithm requires an HMAC secret. Provide a key file or secret containing raw secret bytes.");

        int hashLen = hash.Name switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException($"Unsupported HMAC hash: {hash.Name}"),
        };

        Span<byte> computed = stackalloc byte[64]; // big enough for SHA-512
        computed = computed.Slice(0, hashLen);
        try
        {
            int written = hash.Name switch
            {
                "SHA256" => HMACSHA256.HashData(key.HmacBytes, jwt.SigningInput, computed),
                "SHA384" => HMACSHA384.HashData(key.HmacBytes, jwt.SigningInput, computed),
                "SHA512" => HMACSHA512.HashData(key.HmacBytes, jwt.SigningInput, computed),
                _ => 0,
            };
            if (written != hashLen) return false;
            return CryptographicOperations.FixedTimeEquals(computed, jwt.SignatureBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computed);
        }
    }

    private static bool VerifyRsa(Jwt jwt, KeyMaterial key, HashAlgorithmName hash, RSASignaturePadding padding)
    {
        if (key.Kind != KeyKind.Rsa || key.Rsa is null)
            throw new InvalidOperationException("Algorithm requires an RSA key. Provide a PEM-encoded RSA public key file or an RSA instance.");

        return key.Rsa.VerifyData(jwt.SigningInput, jwt.SignatureBytes, hash, padding);
    }

    private static bool VerifyEcdsa(Jwt jwt, KeyMaterial key, HashAlgorithmName hash, int expectedSig, int expectedKeySize)
    {
        if (key.Kind != KeyKind.Ecdsa || key.Ecdsa is null)
            throw new InvalidOperationException("Algorithm requires an ECDsa key. Provide a PEM-encoded EC public key file or an ECDsa instance.");

        if (key.Ecdsa.KeySize != expectedKeySize)
            throw new InvalidOperationException(
                $"ECDSA key size mismatch: expected P-{expectedKeySize}, got P-{key.Ecdsa.KeySize}.");

        if (jwt.SignatureBytes.Length != expectedSig)
            throw new InvalidOperationException(
                $"ECDSA signature length mismatch: expected {expectedSig} bytes, got {jwt.SignatureBytes.Length}.");

        return key.Ecdsa.VerifyData(
            jwt.SigningInput,
            jwt.SignatureBytes,
            hash,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}
