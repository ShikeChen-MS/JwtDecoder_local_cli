using System.Security.Cryptography;
using System.Text;

namespace JwtDecoder.Core;

/// <summary>
/// Convenience facade over the lower-level <see cref="Jwt"/>, <see cref="JwtVerifier"/>,
/// <see cref="KeyMaterial"/>, and <see cref="KeyLoader"/> APIs.
/// </summary>
/// <remarks>
/// <para>
/// Use these one-liners for common one-shot decode/verify scenarios. Drop down to the
/// underlying types directly when you need more control (e.g. retain the decoded
/// <see cref="Jwt"/> across multiple verifications, share a pre-loaded
/// <see cref="RSA"/> across many tokens, or own the <see cref="KeyMaterial"/> lifetime).
/// </para>
/// <para>
/// All methods preserve the security properties documented on the underlying types:
/// algorithm-confusion guard, JOSE curve binding, private-key refusal, oversized-input
/// rejection, terminal-injection guard, and zeroed-secret memory.
/// </para>
/// </remarks>
public static class JwtTools
{
    /// <summary>
    /// Decode a JWT without cryptographic verification.
    /// The returned <see cref="Jwt"/> owns its parsed buffers — call
    /// <see cref="Jwt.Dispose"/> when done so the header/payload/signature
    /// bytes are zeroed promptly.
    /// </summary>
    /// <param name="token">The compact JWS token. A leading <c>Bearer </c> prefix
    /// and surrounding quotes are tolerated.</param>
    /// <returns>The parsed <see cref="Jwt"/>.</returns>
    /// <exception cref="ArgumentNullException">If <paramref name="token"/> is null.</exception>
    /// <exception cref="FormatException">If the token is malformed (bad base64url,
    /// invalid JSON, duplicate header/payload keys, missing <c>alg</c>, etc.).</exception>
    public static Jwt Decode(string token) => Jwt.Parse(token);

    /// <summary>
    /// Decode a JWT and verify its HMAC signature in one call.
    /// The returned <see cref="Jwt"/> stays alive so the caller can inspect the
    /// header/payload regardless of the verification outcome; the caller MUST
    /// dispose it.
    /// </summary>
    /// <param name="token">The compact JWS token.</param>
    /// <param name="secret">Raw HMAC secret bytes. A defensive copy is made
    /// before use, so the caller's array is not zeroed by this method.</param>
    /// <returns>A tuple containing the decoded <see cref="Jwt"/> and the
    /// <see cref="VerifyOutcome"/>.</returns>
    public static (Jwt Jwt, VerifyOutcome Outcome) DecodeAndVerifyHmac(string token, byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var jwt = Jwt.Parse(token);
        try
        {
            // Copy so the caller's array is not zeroed when KeyMaterial is disposed.
            byte[] copy = (byte[])secret.Clone();
            using var key = KeyLoader.CreateHmacFromBytes(copy, jwt.Algorithm);
            return (jwt, JwtVerifier.Verify(jwt, key));
        }
        catch
        {
            jwt.Dispose();
            throw;
        }
    }

    /// <summary>
    /// One-shot HMAC verification. The token is parsed, verified, and disposed
    /// internally — use <see cref="DecodeAndVerifyHmac(string, byte[])"/> if you
    /// also need the decoded claims.
    /// </summary>
    /// <param name="token">The compact JWS token.</param>
    /// <param name="secret">Raw HMAC secret bytes.</param>
    public static VerifyOutcome VerifyHmac(string token, byte[] secret)
    {
        var (jwt, outcome) = DecodeAndVerifyHmac(token, secret);
        jwt.Dispose();
        return outcome;
    }

    /// <summary>
    /// One-shot HMAC verification with a UTF-8 string secret.
    /// </summary>
    /// <remarks>
    /// The UTF-8 byte array derived from <paramref name="secret"/> is zeroed
    /// after use. The .NET <see cref="string"/> itself is immutable and cannot
    /// be cleared — for the strongest memory-hygiene guarantees, hand in raw
    /// bytes via the <see cref="VerifyHmac(string, byte[])"/> overload.
    /// </remarks>
    public static VerifyOutcome VerifyHmac(string token, string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        byte[] bytes = Encoding.UTF8.GetBytes(secret);
        try { return VerifyHmac(token, bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>
    /// Verify a JWT signed with an RSA algorithm (RS256/384/512 or PS256/384/512)
    /// against a caller-supplied <see cref="RSA"/> instance.
    /// Ownership of <paramref name="rsa"/> stays with the caller.
    /// </summary>
    public static VerifyOutcome VerifyRsa(string token, RSA rsa)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        using var jwt = Jwt.Parse(token);
        using var key = KeyLoader.CreateRsaShared(rsa, jwt.Algorithm);
        return JwtVerifier.Verify(jwt, key);
    }

    /// <summary>
    /// Verify a JWT signed with an ECDsa algorithm (ES256/384/512) against a
    /// caller-supplied <see cref="ECDsa"/> instance. The curve must match the
    /// JOSE binding: ES256↔P-256, ES384↔P-384, ES512↔P-521.
    /// Ownership of <paramref name="ec"/> stays with the caller.
    /// </summary>
    public static VerifyOutcome VerifyEcdsa(string token, ECDsa ec)
    {
        ArgumentNullException.ThrowIfNull(ec);
        using var jwt = Jwt.Parse(token);
        using var key = KeyLoader.CreateEcdsaShared(ec, jwt.Algorithm);
        return JwtVerifier.Verify(jwt, key);
    }

    /// <summary>
    /// Verify a JWT using a key file. The expected file format is inferred from
    /// the JWT's <c>alg</c> header and cross-checked against the file's actual
    /// content — the same algorithm-confusion guard the CLI uses.
    /// </summary>
    /// <remarks>
    /// I/O errors (file missing, unreadable, oversized) and policy errors
    /// (PEM-looking file supplied for an HMAC alg, PEM containing a PRIVATE KEY
    /// block, EC curve mismatch, unsupported algorithm) propagate as exceptions.
    /// Cryptographic failures (signature does not match) are returned as a
    /// <see cref="VerifyOutcome"/> with <c>Verified=false</c>.
    /// </remarks>
    public static VerifyOutcome VerifyWithKeyFile(string token, string keyFilePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyFilePath);
        using var jwt = Jwt.Parse(token);
        using var key = KeyLoader.Load(keyFilePath, jwt.Algorithm);
        return JwtVerifier.Verify(jwt, key);
    }
}
