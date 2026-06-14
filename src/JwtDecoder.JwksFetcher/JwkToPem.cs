using System.Security.Cryptography;

namespace JwtDecoder.JwksFetcher;

/// <summary>
/// Converts a validated <see cref="JwkRecord"/> into a PEM-encoded
/// <c>SubjectPublicKeyInfo</c> block — the exact format the
/// <c>JwtDecoder.Core</c> <c>KeyLoader</c> accepts via <c>--key-file</c>.
/// </summary>
/// <remarks>
/// Only public-key material is emitted. The RSA path uses
/// <see cref="RSA.ImportParameters(RSAParameters)"/> +
/// <c>RSA.ExportSubjectPublicKeyInfoPem()</c>; the EC path uses the
/// equivalent <see cref="ECDsa"/> APIs with the JOSE curve binding enforced
/// by <see cref="JwksDocument"/> upstream.
/// </remarks>
public static class JwkToPem
{
    /// <summary>Emit the JWK as a SubjectPublicKeyInfo PEM block.</summary>
    /// <exception cref="ArgumentNullException">If <paramref name="jwk"/> is null.</exception>
    /// <exception cref="InvalidDataException">If the JWK is missing required fields for its kty.</exception>
    public static string ToPublicKeyPem(JwkRecord jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        return jwk.Kty switch
        {
            "RSA" => RsaToPem(jwk),
            "EC"  => EcToPem(jwk),
            _ => throw new InvalidDataException($"JWK kty='{jwk.Kty}' cannot be exported as a public-key PEM."),
        };
    }

    private static string RsaToPem(JwkRecord jwk)
    {
        if (jwk.N is null || jwk.E is null)
            throw new InvalidDataException("RSA JWK is missing 'n' or 'e'.");

        byte[] nBytes = Base64UrlCodec.Decode(jwk.N);
        byte[] eBytes = Base64UrlCodec.Decode(jwk.E);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = nBytes, Exponent = eBytes });
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    private static string EcToPem(JwkRecord jwk)
    {
        if (jwk.Crv is null || jwk.X is null || jwk.Y is null)
            throw new InvalidDataException("EC JWK is missing 'crv', 'x', or 'y'.");

        ECCurve curve = jwk.Crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidDataException($"EC JWK crv='{jwk.Crv}' is not supported."),
        };

        byte[] xBytes = Base64UrlCodec.Decode(jwk.X);
        byte[] yBytes = Base64UrlCodec.Decode(jwk.Y);

        using var ec = ECDsa.Create();
        ec.ImportParameters(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = xBytes, Y = yBytes },
        });
        return ec.ExportSubjectPublicKeyInfoPem();
    }
}
