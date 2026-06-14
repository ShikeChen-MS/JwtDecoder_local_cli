using System.Security.Cryptography;

namespace JwtDecoder.Jwks.PowerShell;

/// <summary>
/// The output of <c>Get-JsonWebKey</c>: the selected JWK rendered as a public-key
/// PEM block plus a typed asymmetric key ready for verification.
/// </summary>
/// <remarks>
/// The wrapped <see cref="AsymmetricAlgorithm"/> is owned by this object when
/// constructed via <see cref="CreateOwned"/>; <see cref="Dispose"/> releases
/// the native key handle. A finalizer is the safety net for the pipeline form
/// where users don't explicitly dispose. Prefer the explicit pattern in
/// long-running scripts:
/// <code>
/// $jwk = Get-JsonWebKey -JwksFile ./keys.json -Token $t
/// try { Test-JsonWebTokenSignature -Token $t -PublicKey $jwk.PublicKey }
/// finally { $jwk.Dispose() }
/// </code>
/// </remarks>
public sealed class JsonWebKey : IDisposable
{
    private AsymmetricAlgorithm? _publicKey;
    private readonly bool _ownsPublicKey;
    private bool _disposed;

    /// <summary>SubjectPublicKeyInfo PEM (label <c>PUBLIC KEY</c>).</summary>
    public string Pem { get; }

    /// <summary>Effective algorithm for this key (JWK <c>alg</c> if present, otherwise the JWT's alg).</summary>
    public string Algorithm { get; }

    /// <summary>Key type: <c>RSA</c> or <c>EC</c>.</summary>
    public string Kty { get; }

    /// <summary>Optional key identifier from the JWK.</summary>
    public string? Kid { get; }

    /// <summary>EC curve when <see cref="Kty"/> is <c>EC</c> (<c>P-256</c>/<c>P-384</c>/<c>P-521</c>).</summary>
    public string? Crv { get; }

    /// <summary>The URL the JWKS was retrieved from, or <c>null</c> for <c>--JwksFile</c>.</summary>
    public Uri? SourceUri { get; }

    /// <summary>An <see cref="RSA"/> or <see cref="ECDsa"/> ready for verification.</summary>
    public AsymmetricAlgorithm? PublicKey => _disposed ? null : _publicKey;

    internal JsonWebKey(
        string pem,
        string algorithm,
        string kty,
        string? kid,
        string? crv,
        Uri? sourceUri,
        AsymmetricAlgorithm? publicKey,
        bool ownsPublicKey)
    {
        Pem = pem;
        Algorithm = algorithm;
        Kty = kty;
        Kid = kid;
        Crv = crv;
        SourceUri = sourceUri;
        _publicKey = publicKey;
        _ownsPublicKey = ownsPublicKey;
    }

    /// <summary>
    /// Build a <see cref="JsonWebKey"/> from a public-key PEM, taking ownership of
    /// the supplied <see cref="AsymmetricAlgorithm"/>.
    /// </summary>
    public static JsonWebKey CreateOwned(
        string pem, string algorithm, string kty, string? kid, string? crv, Uri? sourceUri,
        AsymmetricAlgorithm publicKey)
        => new(pem, algorithm, kty, kid, crv, sourceUri, publicKey, ownsPublicKey: true);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsPublicKey) _publicKey?.Dispose();
        _publicKey = null;
        GC.SuppressFinalize(this);
    }

    ~JsonWebKey()
    {
        // Safety net for the pipeline form (Get-JsonWebKey | Test-JsonWebTokenSignature):
        // the wrapper goes out of scope without a try/finally; GC eventually
        // releases the RSA/ECDsa handle through us.
        if (!_disposed && _ownsPublicKey) _publicKey?.Dispose();
    }
}
