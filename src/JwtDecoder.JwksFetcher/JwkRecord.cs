namespace JwtDecoder.JwksFetcher;

/// <summary>
/// A single JSON Web Key parsed and validated from a JWKS document.
/// Only fields needed for signature verification are surfaced.
/// </summary>
/// <remarks>
/// Private components (RSA <c>d</c>/<c>p</c>/<c>q</c>/<c>dp</c>/<c>dq</c>/<c>qi</c>,
/// EC <c>d</c>) are refused at parse time and never reach a <see cref="JwkRecord"/>.
/// Remote-reference fields (<c>x5u</c>, <c>jku</c>) are also refused. <c>x5c</c>
/// is silently ignored.
/// </remarks>
public sealed class JwkRecord
{
    /// <summary>Key type. Only <c>"RSA"</c> or <c>"EC"</c> are accepted.</summary>
    public required string Kty { get; init; }

    /// <summary>Optional key identifier (JWK <c>kid</c>).</summary>
    public string? Kid { get; init; }

    /// <summary>Optional algorithm identifier (JWK <c>alg</c>).</summary>
    public string? Alg { get; init; }

    /// <summary>Optional public-key use (JWK <c>use</c>). If present, must be <c>"sig"</c>.</summary>
    public string? Use { get; init; }

    /// <summary>Optional key operations (JWK <c>key_ops</c>). If present, must contain <c>"verify"</c>.</summary>
    public IReadOnlyList<string>? KeyOps { get; init; }

    /// <summary>RSA modulus, base64url-encoded (JWK <c>n</c>). Set only when <c>Kty == "RSA"</c>.</summary>
    public string? N { get; init; }

    /// <summary>RSA exponent, base64url-encoded (JWK <c>e</c>). Set only when <c>Kty == "RSA"</c>.</summary>
    public string? E { get; init; }

    /// <summary>EC curve identifier (JWK <c>crv</c>: <c>"P-256"</c>, <c>"P-384"</c>, or <c>"P-521"</c>). Set only when <c>Kty == "EC"</c>.</summary>
    public string? Crv { get; init; }

    /// <summary>EC X coordinate, base64url-encoded (JWK <c>x</c>). Set only when <c>Kty == "EC"</c>.</summary>
    public string? X { get; init; }

    /// <summary>EC Y coordinate, base64url-encoded (JWK <c>y</c>). Set only when <c>Kty == "EC"</c>.</summary>
    public string? Y { get; init; }
}
