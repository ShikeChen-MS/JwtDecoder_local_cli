using System.Security.Cryptography;
using System.Text;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class JwtVerifierTests
{
    private const string HmacToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string HmacSecret = "your-256-bit-secret";

    // -----------------------------------------------------------------
    // HMAC happy + sad paths
    // -----------------------------------------------------------------

    [Fact]
    public void Verify_HS256_with_correct_secret_returns_verified()
    {
        using var jwt = Jwt.Parse(HmacToken);
        using var key = KeyLoader.CreateHmacFromBytes(Encoding.UTF8.GetBytes(HmacSecret), "HS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.True(outcome.Verified);
        Assert.Equal("HS256", outcome.Algorithm);
        Assert.Null(outcome.Error);
    }

    [Fact]
    public void Verify_HS256_with_wrong_secret_returns_signature_mismatch()
    {
        using var jwt = Jwt.Parse(HmacToken);
        using var key = KeyLoader.CreateHmacFromBytes(Encoding.UTF8.GetBytes("not-the-right-secret"), "HS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.False(outcome.Verified);
        Assert.Equal("HS256", outcome.Algorithm);
        Assert.NotNull(outcome.Error);
        Assert.Contains("does not match", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_with_null_key_returns_outcome_with_descriptive_error()
    {
        using var jwt = Jwt.Parse(HmacToken);
        var outcome = JwtVerifier.Verify(jwt, null);
        Assert.False(outcome.Verified);
        Assert.Contains("No key material", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_with_empty_signature_returns_descriptive_error()
    {
        // header = {"alg":"HS256"} ; payload = {"sub":"x"} ; signature empty
        string token =
            "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ4In0." +
            "";
        using var jwt = Jwt.Parse(token);
        using var key = KeyLoader.CreateHmacFromBytes(Encoding.UTF8.GetBytes("secret"), "HS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.False(outcome.Verified);
        Assert.Contains("Signature segment is empty", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_with_mismatched_key_kind_returns_outcome_with_invalid_operation_message()
    {
        // HMAC token verified against an RSA key — Verify converts the InvalidOperationException
        // into a friendly VerifyOutcome rather than throwing.
        using var jwt = Jwt.Parse(HmacToken);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(TestSamples.Path("rs256-public.pem")));
        using var key = KeyMaterial.CreateRsaShared(rsa);
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.False(outcome.Verified);
        Assert.NotNull(outcome.Error);
    }

    [Fact]
    public void Verify_null_jwt_throws_argument_null()
    {
        Assert.Throws<ArgumentNullException>(() => JwtVerifier.Verify(null!, null));
    }

    // -----------------------------------------------------------------
    // alg=none is always rejected with a security warning
    // -----------------------------------------------------------------

    [Fact]
    public void Verify_alg_none_always_returns_false_with_security_warning()
    {
        using var jwt = Jwt.Parse(TestSamples.ReadText("alg-none.jwt"));
        using var key = KeyLoader.CreateHmacFromBytes("anything"u8, "HS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.False(outcome.Verified);
        Assert.Equal("none", outcome.Algorithm);
        Assert.Contains("red flag", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_alg_none_with_null_key_also_returns_false_with_security_warning()
    {
        using var jwt = Jwt.Parse(TestSamples.ReadText("alg-none.jwt"));
        var outcome = JwtVerifier.Verify(jwt, null);
        Assert.False(outcome.Verified);
        Assert.Contains("red flag", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    // -----------------------------------------------------------------
    // RSA / PSS happy paths from sample tokens
    // -----------------------------------------------------------------

    [Fact]
    public void Verify_RS256_sample_token_with_public_key_succeeds()
    {
        using var jwt = Jwt.Parse(TestSamples.ReadText("rs256-token.jwt"));
        using var key = KeyLoader.Load(TestSamples.Path("rs256-public.pem"), "RS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.True(outcome.Verified);
        Assert.Equal("RS256", outcome.Algorithm);
    }

    [Fact]
    public void Verify_PS256_sample_token_with_same_RSA_public_key_succeeds()
    {
        using var jwt = Jwt.Parse(TestSamples.ReadText("ps256-token.jwt"));
        using var key = KeyLoader.Load(TestSamples.Path("rs256-public.pem"), "PS256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.True(outcome.Verified);
        Assert.Equal("PS256", outcome.Algorithm);
    }

    // -----------------------------------------------------------------
    // ECDsa happy + sad paths from sample tokens
    // -----------------------------------------------------------------

    [Fact]
    public void Verify_ES256_sample_token_with_P256_key_succeeds()
    {
        using var jwt = Jwt.Parse(TestSamples.ReadText("es256-token.jwt"));
        using var key = KeyLoader.Load(TestSamples.Path("es256-public.pem"), "ES256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.True(outcome.Verified);
        Assert.Equal("ES256", outcome.Algorithm);
    }

    [Fact]
    public void Verify_ES256_signature_length_mismatch_returns_outcome_with_error()
    {
        // The "wrong-curve" sample is signed with P-384 but presents alg=ES256, so the signature
        // is the wrong length (96 vs 64) — Verify converts the InvalidOperationException into a
        // failure outcome rather than throwing.
        using var jwt = Jwt.Parse(TestSamples.ReadText("es256-wrong-curve.jwt"));
        using var key = KeyLoader.Load(TestSamples.Path("es256-public.pem"), "ES256");
        var outcome = JwtVerifier.Verify(jwt, key);
        Assert.False(outcome.Verified);
        Assert.NotNull(outcome.Error);
        Assert.Contains("ECDSA signature length mismatch", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }
}
