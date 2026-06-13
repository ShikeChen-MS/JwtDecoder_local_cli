using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace JwtDecoder.Core;

/// <summary>
/// Loads verification key material from a file, enforcing security guarantees:
/// </summary>
/// <list type="bullet">
/// <item>The file format is decided by the JWT's algorithm AND cross-checked against the file's actual contents (algorithm-confusion guard).</item>
/// <item>PEM files containing a PRIVATE KEY block are refused — verification only needs the public key.</item>
/// <item>For ES* algorithms, the EC key's curve must match the JOSE binding (ES256↔P-256, ES384↔P-384, ES512↔P-521).</item>
/// <item>Files exceeding <see cref="MaxKeyFileBytes"/> are refused.</item>
/// <item>All intermediate byte / char buffers are zeroed in <c>finally</c> blocks.</item>
/// </list>
public static class KeyLoader
{
    /// <summary>Real key files are well under 1 KiB. 64 KiB is a generous DoS bound.</summary>
    public const int MaxKeyFileBytes = 64 * 1024;

    /// <summary>Algorithms whose signatures we can verify.</summary>
    public static readonly IReadOnlySet<string> SupportedAlgorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        "HS256","HS384","HS512",
        "RS256","RS384","RS512",
        "PS256","PS384","PS512",
        "ES256","ES384","ES512",
    };

    /// <summary>
    /// Load a key from <paramref name="path"/> appropriate for the JWT's <paramref name="algorithm"/>.
    /// </summary>
    public static KeyMaterial Load(string path, string algorithm)
    {
        if (!SupportedAlgorithms.Contains(algorithm))
            throw new NotSupportedException(
                $"Verification is not supported for algorithm '{algorithm}'. " +
                "Supported: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.");

        byte[] fileBytes = ReadBoundedFile(path, MaxKeyFileBytes);
        try
        {
            return LoadFromBytes(fileBytes, algorithm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    /// <summary>
    /// Load a key from raw <paramref name="bytes"/> appropriate for the JWT's
    /// <paramref name="algorithm"/>, applying the same hardening as
    /// <see cref="Load(string, string)"/>: algorithm-confusion guard
    /// (PEM-looking input rejected for HMAC algorithms), private-key refusal,
    /// JOSE curve binding, and size cap.
    /// </summary>
    /// <param name="bytes">Raw key material. Must be ≤ <see cref="MaxKeyFileBytes"/>.</param>
    /// <param name="algorithm">The JWT's <c>alg</c> header value.</param>
    /// <remarks>
    /// The input span is copied into a fresh buffer that is zeroed in a
    /// <c>finally</c> block; callers should also zero their own buffer.
    /// Intended for stdin / in-process key loading where the bytes are not
    /// on disk.
    /// </remarks>
    public static KeyMaterial LoadFromBytes(ReadOnlySpan<byte> bytes, string algorithm)
    {
        if (!SupportedAlgorithms.Contains(algorithm))
            throw new NotSupportedException(
                $"Verification is not supported for algorithm '{algorithm}'. " +
                "Supported: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512.");

        if (bytes.Length > MaxKeyFileBytes)
            throw new InvalidDataException(
                $"Key bytes exceed maximum size of {MaxKeyFileBytes:N0} bytes.");
        if (bytes.IsEmpty)
            throw new InvalidDataException("Key bytes are empty.");

        byte[] copy = new byte[bytes.Length];
        bytes.CopyTo(copy);
        try
        {
            return LoadFromBytes(copy, algorithm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    /// <summary>
    /// Build an HMAC <see cref="KeyMaterial"/> from raw secret bytes, with the same algorithm-confusion guard
    /// applied to file inputs (refusing input that looks like PEM).
    /// </summary>
    /// <remarks>
    /// The caller-supplied <paramref name="secretBytes"/> is COPIED into a fresh buffer owned by the returned
    /// <see cref="KeyMaterial"/>; the caller still owns and should zero <paramref name="secretBytes"/> itself.
    /// </remarks>
    public static KeyMaterial CreateHmacFromBytes(ReadOnlySpan<byte> secretBytes, string algorithm)
    {
        if (algorithm is not ("HS256" or "HS384" or "HS512"))
            throw new InvalidOperationException(
                $"CreateHmacFromBytes is only valid for HMAC algorithms; got '{algorithm}'.");

        if (LooksLikePem(secretBytes))
            throw new InvalidDataException(
                "Refusing to use a PEM-formatted byte sequence as an HMAC secret. " +
                "This guards against the JWT algorithm-confusion attack where a public key is repurposed as an HMAC secret.");

        if (secretBytes.Length == 0)
            throw new InvalidDataException("HMAC secret is empty.");

        byte[] secret = new byte[secretBytes.Length];
        secretBytes.CopyTo(secret);
        return KeyMaterial.CreateHmac(secret);
    }

    /// <summary>
    /// Wrap an already-loaded <see cref="RSA"/> for verification. Ownership stays with the caller.
    /// </summary>
    public static KeyMaterial CreateRsaShared(RSA rsa, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        if (algorithm is not ("RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512"))
            throw new InvalidOperationException(
                $"CreateRsaShared is only valid for RS*/PS* algorithms; got '{algorithm}'.");
        return KeyMaterial.CreateRsaShared(rsa);
    }

    /// <summary>
    /// Wrap an already-loaded <see cref="ECDsa"/> for verification. Ownership stays with the caller.
    /// Enforces the JOSE curve binding.
    /// </summary>
    public static KeyMaterial CreateEcdsaShared(ECDsa ec, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(ec);
        int expectedSize = algorithm switch
        {
            "ES256" => 256,
            "ES384" => 384,
            "ES512" => 521,
            _ => throw new InvalidOperationException(
                $"CreateEcdsaShared is only valid for ES* algorithms; got '{algorithm}'."),
        };
        if (ec.KeySize != expectedSize)
            throw new InvalidDataException(
                $"Algorithm '{algorithm}' requires a P-{expectedSize} curve, but the supplied key is P-{ec.KeySize}.");
        return KeyMaterial.CreateEcdsaShared(ec);
    }

    private static KeyMaterial LoadFromBytes(byte[] fileBytes, string algorithm)
    {
        bool looksPem = LooksLikePem(fileBytes);
        if (looksPem) RejectPrivateKeyPem(fileBytes);

        if (algorithm is "HS256" or "HS384" or "HS512")
        {
            if (looksPem)
                throw new InvalidDataException(
                    "Refusing to use a PEM-formatted file as an HMAC secret. " +
                    "The JWT declares an HMAC algorithm but the key file looks like PEM. " +
                    "This guards against the JWT algorithm-confusion attack where a public key is repurposed as an HMAC secret.");

            int length = fileBytes.Length;
            if (length >= 2 && fileBytes[length - 2] == (byte)'\r' && fileBytes[length - 1] == (byte)'\n') length -= 2;
            else if (length >= 1 && fileBytes[length - 1] == (byte)'\n') length -= 1;
            if (length == 0)
                throw new InvalidDataException("HMAC secret file is empty (after stripping trailing newline).");

            byte[] secret = new byte[length];
            fileBytes.AsSpan(0, length).CopyTo(secret);
            return KeyMaterial.CreateHmac(secret);
        }

        if (!looksPem)
            throw new InvalidDataException(
                $"Algorithm '{algorithm}' requires a PEM-encoded public key, but the file does not contain a PEM block.");

        int charCount = Encoding.UTF8.GetCharCount(fileBytes);
        char[] chars = new char[charCount];
        try
        {
            int written = Encoding.UTF8.GetChars(fileBytes, chars);

            if (algorithm is "RS256" or "RS384" or "RS512"
                          or "PS256" or "PS384" or "PS512")
            {
                var rsa = RSA.Create();
                try
                {
                    rsa.ImportFromPem(chars.AsSpan(0, written));
                }
                catch (Exception ex)
                {
                    rsa.Dispose();
                    throw new InvalidDataException(
                        "Failed to load RSA public key from PEM file. " +
                        "Expected a PEM-encoded RSA public key (label 'PUBLIC KEY' or 'RSA PUBLIC KEY'). " + ex.Message, ex);
                }
                return KeyMaterial.CreateRsa(rsa);
            }

            var ec = ECDsa.Create();
            try
            {
                ec.ImportFromPem(chars.AsSpan(0, written));
            }
            catch (Exception ex)
            {
                ec.Dispose();
                throw new InvalidDataException(
                    "Failed to load EC public key from PEM file. " +
                    "Expected a PEM-encoded EC public key. " + ex.Message, ex);
            }

            int expectedSize = algorithm switch
            {
                "ES256" => 256,
                "ES384" => 384,
                "ES512" => 521,
                _ => 0,
            };
            if (ec.KeySize != expectedSize)
            {
                int actual = ec.KeySize;
                ec.Dispose();
                throw new InvalidDataException(
                    $"Algorithm '{algorithm}' requires a P-{expectedSize} curve, but the key file is P-{actual}.");
            }
            return KeyMaterial.CreateEcdsa(ec);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
        }
    }

    private static byte[] ReadBoundedFile(string path, int maxBytes)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: false);

        long known = -1;
        try { known = fs.Length; } catch { /* not seekable */ }
        if (known > maxBytes)
            throw new InvalidDataException($"Key file is too large ({known:N0} bytes; max {maxBytes:N0}).");

        byte[] buf = new byte[maxBytes + 1];
        int total = 0;
        while (total < buf.Length)
        {
            int n = fs.Read(buf, total, buf.Length - total);
            if (n == 0) break;
            total += n;
        }
        if (total > maxBytes)
        {
            CryptographicOperations.ZeroMemory(buf);
            throw new InvalidDataException($"Key file exceeds maximum size of {maxBytes:N0} bytes.");
        }

        byte[] exact = new byte[total];
        buf.AsSpan(0, total).CopyTo(exact);
        CryptographicOperations.ZeroMemory(buf);
        return exact;
    }

    private static bool LooksLikePem(ReadOnlySpan<byte> bytes)
    {
        ReadOnlySpan<byte> marker = "-----BEGIN "u8;
        int scan = Math.Min(bytes.Length, 4096);
        return bytes.Slice(0, scan).IndexOf(marker) >= 0;
    }

    private static void RejectPrivateKeyPem(ReadOnlySpan<byte> bytes)
    {
        ReadOnlySpan<byte> marker = "PRIVATE KEY"u8;
        int scan = Math.Min(bytes.Length, 8192);
        if (bytes.Slice(0, scan).IndexOf(marker) >= 0)
            throw new InvalidDataException(
                "Refusing to load a private key for verification. " +
                "Verification only requires the PUBLIC key — using the private key would expose secret material with no benefit. " +
                "Provide a PEM file containing only the public key.");
    }
}
