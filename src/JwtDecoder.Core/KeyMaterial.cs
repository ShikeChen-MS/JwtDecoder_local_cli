using System.Security.Cryptography;

namespace JwtDecoder.Core;

public enum KeyKind { Hmac, Rsa, Ecdsa }

/// <summary>
/// Holds verification key material. Disposing zeroes the HMAC secret bytes (if owned)
/// and disposes the crypto provider (if owned).
/// </summary>
/// <remarks>
/// When created via the <c>Shared</c> factories, the caller retains ownership of the
/// <see cref="RSA"/> / <see cref="ECDsa"/> instance and this object will not dispose it.
/// </remarks>
public sealed class KeyMaterial : IDisposable
{
    public KeyKind Kind { get; }
    public byte[]? HmacBytes { get; }
    public RSA? Rsa { get; }
    public ECDsa? Ecdsa { get; }
    public bool OwnsCryptoProvider { get; }

    private bool _disposed;

    private KeyMaterial(KeyKind kind, byte[]? hmac, RSA? rsa, ECDsa? ec, bool owns)
    {
        Kind = kind; HmacBytes = hmac; Rsa = rsa; Ecdsa = ec; OwnsCryptoProvider = owns;
    }

    /// <summary>Create from HMAC secret bytes. The bytes are zeroed on <see cref="Dispose"/>.</summary>
    public static KeyMaterial CreateHmac(byte[] bytes)       => new(KeyKind.Hmac, bytes, null, null, owns: true);

    /// <summary>Create from an RSA instance. The instance is disposed on <see cref="Dispose"/>.</summary>
    public static KeyMaterial CreateRsa(RSA rsa)             => new(KeyKind.Rsa,   null, rsa, null, owns: true);

    /// <summary>Create from a shared RSA instance. The caller retains ownership.</summary>
    public static KeyMaterial CreateRsaShared(RSA rsa)       => new(KeyKind.Rsa,   null, rsa, null, owns: false);

    /// <summary>Create from an ECDsa instance. The instance is disposed on <see cref="Dispose"/>.</summary>
    public static KeyMaterial CreateEcdsa(ECDsa ec)          => new(KeyKind.Ecdsa, null, null, ec,  owns: true);

    /// <summary>Create from a shared ECDsa instance. The caller retains ownership.</summary>
    public static KeyMaterial CreateEcdsaShared(ECDsa ec)    => new(KeyKind.Ecdsa, null, null, ec,  owns: false);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (HmacBytes is not null) CryptographicOperations.ZeroMemory(HmacBytes);
        if (OwnsCryptoProvider)
        {
            Rsa?.Dispose();
            Ecdsa?.Dispose();
        }
    }
}
