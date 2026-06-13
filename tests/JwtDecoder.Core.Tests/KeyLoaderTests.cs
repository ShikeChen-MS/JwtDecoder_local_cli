using System.Security.Cryptography;
using System.Text;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class KeyLoaderTests
{
    // -----------------------------------------------------------------
    // HMAC: raw secret loading + trailing-newline stripping + alg-confusion guard
    // -----------------------------------------------------------------

    [Fact]
    public void Load_HMAC_returns_secret_bytes_from_file()
    {
        string path = TestSamples.Path("hs256-secret.txt");
        using var key = KeyLoader.Load(path, "HS256");
        Assert.Equal(KeyKind.Hmac, key.Kind);
        Assert.NotNull(key.HmacBytes);
        Assert.NotEmpty(key.HmacBytes!);
    }

    [Theory]
    [InlineData("secret", "\n", "secret")]      // single LF stripped
    [InlineData("secret", "\r\n", "secret")]    // single CRLF stripped
    [InlineData("secret\n", "\n", "secret\n")]  // only the trailing newline is stripped
    [InlineData("secret", "", "secret")]        // no trailing newline
    public void Load_HMAC_strips_a_single_trailing_newline_only(string body, string suffix, string expected)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(body + suffix));
            using var key = KeyLoader.Load(path, "HS256");
            Assert.Equal(expected, Encoding.UTF8.GetString(key.HmacBytes!));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Load_HMAC_with_PEM_looking_file_refuses_as_algorithm_confusion()
    {
        string path = TestSamples.Path("rs256-public.pem");
        var ex = Assert.Throws<InvalidDataException>(() => KeyLoader.Load(path, "HS256"));
        Assert.Contains("algorithm-confusion", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_HMAC_with_empty_file_throws()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Array.Empty<byte>());
            Assert.Throws<InvalidDataException>(() => KeyLoader.Load(path, "HS256"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void CreateHmacFromBytes_returns_owned_copy_independent_of_caller_buffer()
    {
        byte[] caller = Encoding.UTF8.GetBytes("hello-secret");
        using var key = KeyLoader.CreateHmacFromBytes(caller, "HS256");
        Assert.NotSame(caller, key.HmacBytes);
        Array.Clear(caller, 0, caller.Length);          // wipe caller buffer
        Assert.Equal("hello-secret", Encoding.UTF8.GetString(key.HmacBytes!));
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    [InlineData("ES256")]
    public void CreateHmacFromBytes_refuses_non_HMAC_algorithm(string alg)
    {
        Assert.Throws<InvalidOperationException>(
            () => KeyLoader.CreateHmacFromBytes("x"u8, alg));
    }

    [Fact]
    public void CreateHmacFromBytes_refuses_PEM_looking_bytes()
    {
        byte[] pemLike = Encoding.UTF8.GetBytes("-----BEGIN PUBLIC KEY-----\nXYZ\n-----END PUBLIC KEY-----");
        Assert.Throws<InvalidDataException>(() => KeyLoader.CreateHmacFromBytes(pemLike, "HS256"));
    }

    [Fact]
    public void CreateHmacFromBytes_refuses_empty_secret()
    {
        Assert.Throws<InvalidDataException>(() => KeyLoader.CreateHmacFromBytes(Array.Empty<byte>(), "HS256"));
    }

    // -----------------------------------------------------------------
    // RSA: PEM loading + private-key refusal + non-PEM refusal
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    public void Load_RSA_public_PEM_succeeds_for_all_RSA_family_algorithms(string alg)
    {
        using var key = KeyLoader.Load(TestSamples.Path("rs256-public.pem"), alg);
        Assert.Equal(KeyKind.Rsa, key.Kind);
        Assert.NotNull(key.Rsa);
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    public void Load_RSA_with_private_key_PEM_is_refused(string alg)
    {
        var ex = Assert.Throws<InvalidDataException>(
            () => KeyLoader.Load(TestSamples.Path("rsa-private.pem"), alg));
        Assert.Contains("private key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_RSA_with_non_PEM_HMAC_secret_file_is_refused()
    {
        var ex = Assert.Throws<InvalidDataException>(
            () => KeyLoader.Load(TestSamples.Path("hs256-secret.txt"), "RS256"));
        Assert.Contains("PEM", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateRsaShared_returns_keymaterial_that_does_not_dispose_caller_instance()
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(TestSamples.Path("rs256-public.pem")));

        var km = KeyLoader.CreateRsaShared(rsa, "RS256");
        km.Dispose();
        // If the disposed KeyMaterial had taken ownership, the next call would throw ObjectDisposedException.
        Assert.True(rsa.KeySize > 0);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("ES256")]
    public void CreateRsaShared_refuses_non_RSA_algorithm(string alg)
    {
        using var rsa = RSA.Create();
        Assert.Throws<InvalidOperationException>(() => KeyLoader.CreateRsaShared(rsa, alg));
    }

    // -----------------------------------------------------------------
    // ECDsa: PEM loading + curve binding
    // -----------------------------------------------------------------

    [Fact]
    public void Load_ES256_with_P256_PEM_succeeds()
    {
        using var key = KeyLoader.Load(TestSamples.Path("es256-public.pem"), "ES256");
        Assert.Equal(KeyKind.Ecdsa, key.Kind);
        Assert.NotNull(key.Ecdsa);
        Assert.Equal(256, key.Ecdsa!.KeySize);
    }

    [Fact]
    public void Load_ES256_with_P384_PEM_refused_with_curve_mismatch_error()
    {
        var ex = Assert.Throws<InvalidDataException>(
            () => KeyLoader.Load(TestSamples.Path("es384-public.pem"), "ES256"));
        Assert.Contains("P-256", ex.Message);
        Assert.Contains("P-384", ex.Message);
    }

    [Fact]
    public void CreateEcdsaShared_returns_keymaterial_for_matching_curve()
    {
        using var ec = ECDsa.Create();
        ec.ImportFromPem(File.ReadAllText(TestSamples.Path("es256-public.pem")));
        using var km = KeyLoader.CreateEcdsaShared(ec, "ES256");
        Assert.Equal(KeyKind.Ecdsa, km.Kind);
    }

    [Fact]
    public void CreateEcdsaShared_refuses_curve_mismatch()
    {
        using var ec = ECDsa.Create();
        ec.ImportFromPem(File.ReadAllText(TestSamples.Path("es384-public.pem")));
        Assert.Throws<InvalidDataException>(() => KeyLoader.CreateEcdsaShared(ec, "ES256"));
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("RS256")]
    public void CreateEcdsaShared_refuses_non_EC_algorithm(string alg)
    {
        using var ec = ECDsa.Create();
        Assert.Throws<InvalidOperationException>(() => KeyLoader.CreateEcdsaShared(ec, alg));
    }

    // -----------------------------------------------------------------
    // Bookkeeping: unsupported algorithms, oversized file, missing file
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("none")]
    [InlineData("HS128")]
    [InlineData("FOO")]
    [InlineData("")]
    public void Load_unsupported_algorithm_throws_NotSupportedException(string alg)
    {
        Assert.Throws<NotSupportedException>(() => KeyLoader.Load(TestSamples.Path("hs256-secret.txt"), alg));
    }

    [Fact]
    public void Load_oversized_key_file_is_refused()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, new byte[KeyLoader.MaxKeyFileBytes + 1]);
            Assert.Throws<InvalidDataException>(() => KeyLoader.Load(path, "HS256"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Load_missing_key_file_throws_FileNotFoundException()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".key");
        Assert.Throws<FileNotFoundException>(() => KeyLoader.Load(path, "HS256"));
    }

    [Fact]
    public void SupportedAlgorithms_contains_every_documented_alg()
    {
        var expected = new[]
        {
            "HS256","HS384","HS512",
            "RS256","RS384","RS512",
            "PS256","PS384","PS512",
            "ES256","ES384","ES512",
        };
        foreach (var alg in expected)
            Assert.Contains(alg, KeyLoader.SupportedAlgorithms);
    }

    // -----------------------------------------------------------------
    // LoadFromBytes (public overload introduced in Phase 3 for --key-file -)
    // -----------------------------------------------------------------

    [Fact]
    public void LoadFromBytes_HMAC_returns_secret_bytes()
    {
        byte[] secret = Encoding.UTF8.GetBytes("super-secret-value");
        using var key = KeyLoader.LoadFromBytes(secret, "HS256");
        Assert.Equal(KeyKind.Hmac, key.Kind);
        Assert.Equal(secret, key.HmacBytes);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void LoadFromBytes_HMAC_works_for_all_HS_algorithms(string alg)
    {
        byte[] secret = Encoding.UTF8.GetBytes("a-secret-long-enough-for-any-hash-12345678");
        using var key = KeyLoader.LoadFromBytes(secret, alg);
        Assert.Equal(KeyKind.Hmac, key.Kind);
    }

    [Fact]
    public void LoadFromBytes_HMAC_with_PEM_looking_bytes_is_refused_as_algorithm_confusion()
    {
        byte[] pem = File.ReadAllBytes(TestSamples.Path("rs256-public.pem"));
        var ex = Assert.Throws<InvalidDataException>(() => KeyLoader.LoadFromBytes(pem, "HS256"));
        Assert.Contains("algorithm-confusion", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    public void LoadFromBytes_RSA_PEM_succeeds(string alg)
    {
        byte[] pem = File.ReadAllBytes(TestSamples.Path("rs256-public.pem"));
        using var key = KeyLoader.LoadFromBytes(pem, alg);
        Assert.Equal(KeyKind.Rsa, key.Kind);
    }

    [Fact]
    public void LoadFromBytes_RSA_with_private_key_PEM_is_refused()
    {
        byte[] pem = File.ReadAllBytes(TestSamples.Path("rsa-private.pem"));
        Assert.Throws<InvalidDataException>(() => KeyLoader.LoadFromBytes(pem, "RS256"));
    }

    [Fact]
    public void LoadFromBytes_ES256_with_P256_PEM_succeeds()
    {
        byte[] pem = File.ReadAllBytes(TestSamples.Path("es256-public.pem"));
        using var key = KeyLoader.LoadFromBytes(pem, "ES256");
        Assert.Equal(KeyKind.Ecdsa, key.Kind);
    }

    [Fact]
    public void LoadFromBytes_ES256_with_P384_PEM_refused()
    {
        byte[] pem = File.ReadAllBytes(TestSamples.Path("es384-public.pem"));
        Assert.Throws<InvalidDataException>(() => KeyLoader.LoadFromBytes(pem, "ES256"));
    }

    [Fact]
    public void LoadFromBytes_oversized_input_is_refused()
    {
        var huge = new byte[KeyLoader.MaxKeyFileBytes + 1];
        Assert.Throws<InvalidDataException>(() => KeyLoader.LoadFromBytes(huge, "HS256"));
    }

    [Fact]
    public void LoadFromBytes_empty_input_is_refused()
    {
        Assert.Throws<InvalidDataException>(() => KeyLoader.LoadFromBytes(ReadOnlySpan<byte>.Empty, "HS256"));
    }

    [Fact]
    public void LoadFromBytes_unsupported_algorithm_throws()
    {
        Assert.Throws<NotSupportedException>(() =>
            KeyLoader.LoadFromBytes(new byte[] { 1, 2, 3 }, "FOO"));
    }

    [Fact]
    public void LoadFromBytes_copies_caller_buffer()
    {
        // Mutating the caller's buffer after the call must not affect the loaded key.
        byte[] secret = Encoding.UTF8.GetBytes("original");
        using var key = KeyLoader.LoadFromBytes(secret, "HS256");
        secret.AsSpan().Clear();
        Assert.Equal(Encoding.UTF8.GetBytes("original"), key.HmacBytes);
    }
}
