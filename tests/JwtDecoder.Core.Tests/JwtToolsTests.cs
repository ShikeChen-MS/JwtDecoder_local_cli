using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class JwtToolsTests
{
    private const string HmacToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string HmacSecret = "your-256-bit-secret";

    // -----------------------------------------------------------------
    // Decode
    // -----------------------------------------------------------------

    [Fact]
    public void Decode_returns_parsed_jwt_with_expected_alg()
    {
        using var jwt = JwtTools.Decode(HmacToken);
        Assert.Equal("HS256", jwt.Algorithm);
    }

    [Fact]
    public void Decode_propagates_FormatException_for_malformed_input()
    {
        Assert.Throws<FormatException>(() => JwtTools.Decode("not.a.jwt"));
    }

    // -----------------------------------------------------------------
    // VerifyHmac (bytes / string overloads)
    // -----------------------------------------------------------------

    [Fact]
    public void VerifyHmac_with_correct_byte_secret_returns_verified()
    {
        var outcome = JwtTools.VerifyHmac(HmacToken, Encoding.UTF8.GetBytes(HmacSecret));
        Assert.True(outcome.Verified);
    }

    [Fact]
    public void VerifyHmac_with_wrong_byte_secret_returns_unverified()
    {
        var outcome = JwtTools.VerifyHmac(HmacToken, Encoding.UTF8.GetBytes("nope"));
        Assert.False(outcome.Verified);
    }

    [Fact]
    public void VerifyHmac_string_overload_round_trips()
    {
        Assert.True (JwtTools.VerifyHmac(HmacToken, HmacSecret).Verified);
        Assert.False(JwtTools.VerifyHmac(HmacToken, "wrong").Verified);
    }

    [Fact]
    public void VerifyHmac_does_not_mutate_caller_supplied_byte_array()
    {
        byte[] secret = Encoding.UTF8.GetBytes(HmacSecret);
        byte[] snapshot = (byte[])secret.Clone();
        _ = JwtTools.VerifyHmac(HmacToken, secret);
        Assert.Equal(snapshot, secret);
    }

    [Fact]
    public void VerifyHmac_null_secret_throws()
    {
        Assert.Throws<ArgumentNullException>(() => JwtTools.VerifyHmac(HmacToken, (byte[])null!));
        Assert.Throws<ArgumentNullException>(() => JwtTools.VerifyHmac(HmacToken, (string)null!));
    }

    // -----------------------------------------------------------------
    // DecodeAndVerifyHmac
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeAndVerifyHmac_returns_both_decoded_jwt_and_outcome()
    {
        var (jwt, outcome) = JwtTools.DecodeAndVerifyHmac(HmacToken, Encoding.UTF8.GetBytes(HmacSecret));
        using (jwt)
        {
            Assert.Equal("HS256", jwt.Algorithm);
            Assert.True(outcome.Verified);
        }
    }

    [Fact]
    public void DecodeAndVerifyHmac_with_wrong_secret_still_returns_decoded_jwt_for_inspection()
    {
        var (jwt, outcome) = JwtTools.DecodeAndVerifyHmac(HmacToken, Encoding.UTF8.GetBytes("nope"));
        using (jwt)
        {
            Assert.False(outcome.Verified);
            Assert.Equal("1234567890", jwt.Payload.RootElement.GetProperty("sub").GetString());
        }
    }

    [Fact]
    public void DecodeAndVerifyHmac_does_not_mutate_caller_secret()
    {
        byte[] secret = Encoding.UTF8.GetBytes(HmacSecret);
        byte[] snapshot = (byte[])secret.Clone();
        var (jwt, _) = JwtTools.DecodeAndVerifyHmac(HmacToken, secret);
        jwt.Dispose();
        Assert.Equal(snapshot, secret);
    }

    // -----------------------------------------------------------------
    // VerifyRsa / VerifyEcdsa with caller-supplied instances
    // -----------------------------------------------------------------

    [Fact]
    public void VerifyRsa_with_caller_supplied_public_key_returns_verified_for_RS256()
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(TestSamples.Path("rs256-public.pem")));
        var outcome = JwtTools.VerifyRsa(TestSamples.ReadText("rs256-token.jwt"), rsa);
        Assert.True(outcome.Verified);
    }

    [Fact]
    public void VerifyEcdsa_with_caller_supplied_public_key_returns_verified_for_ES256()
    {
        using var ec = ECDsa.Create();
        ec.ImportFromPem(File.ReadAllText(TestSamples.Path("es256-public.pem")));
        var outcome = JwtTools.VerifyEcdsa(TestSamples.ReadText("es256-token.jwt"), ec);
        Assert.True(outcome.Verified);
    }

    [Fact]
    public void VerifyRsa_null_rsa_throws()
    {
        Assert.Throws<ArgumentNullException>(() => JwtTools.VerifyRsa(HmacToken, null!));
    }

    [Fact]
    public void VerifyEcdsa_null_ec_throws()
    {
        Assert.Throws<ArgumentNullException>(() => JwtTools.VerifyEcdsa(HmacToken, null!));
    }

    // -----------------------------------------------------------------
    // VerifyWithKeyFile
    // -----------------------------------------------------------------

    [Fact]
    public void VerifyWithKeyFile_HMAC_succeeds_with_matching_secret_file()
    {
        var outcome = JwtTools.VerifyWithKeyFile(
            TestSamples.ReadText("hs256-token.jwt"),
            TestSamples.Path("hs256-secret.txt"));
        Assert.True(outcome.Verified);
    }

    [Fact]
    public void VerifyWithKeyFile_HMAC_fails_with_wrong_secret_file()
    {
        var outcome = JwtTools.VerifyWithKeyFile(
            TestSamples.ReadText("hs256-token.jwt"),
            TestSamples.Path("hs256-wrong.txt"));
        Assert.False(outcome.Verified);
    }

    [Fact]
    public void VerifyWithKeyFile_blocks_HS256_with_PEM_keyfile()
    {
        // The HS256 + PEM combination is the classic algorithm-confusion attack vector.
        Assert.Throws<InvalidDataException>(() =>
            JwtTools.VerifyWithKeyFile(
                TestSamples.ReadText("hs256-token.jwt"),
                TestSamples.Path("rs256-public.pem")));
    }

    [Fact]
    public void VerifyWithKeyFile_null_or_empty_path_throws()
    {
        // ArgumentException.ThrowIfNullOrEmpty throws ArgumentNullException for null and
        // ArgumentException for "" — we accept either via the common base type.
        Assert.Throws<ArgumentException>(() => JwtTools.VerifyWithKeyFile(HmacToken, ""));
        Assert.Throws<ArgumentNullException>(() => JwtTools.VerifyWithKeyFile(HmacToken, null!));
    }

    // -----------------------------------------------------------------
    // TryQuery / Query one-shot — clone semantics
    // -----------------------------------------------------------------

    [Fact]
    public void TryQuery_returns_clone_safe_to_use_after_method_returns()
    {
        Assert.True(JwtTools.TryQuery(HmacToken, "payload.sub", out JsonElement el));
        // The internal Jwt has already been disposed; if the element were still tied to it,
        // GetString() would throw ObjectDisposedException.
        Assert.Equal("1234567890", el.GetString());
    }

    [Fact]
    public void TryQuery_missing_path_returns_false_and_default_value()
    {
        Assert.False(JwtTools.TryQuery(HmacToken, "payload.nope", out JsonElement el));
        Assert.Equal(JsonValueKind.Undefined, el.ValueKind);
    }

    [Fact]
    public void Query_returns_cloned_element_for_present_path()
    {
        JsonElement? el = JwtTools.Query(HmacToken, "header.alg");
        Assert.NotNull(el);
        Assert.Equal("HS256", el!.Value.GetString());
    }

    [Fact]
    public void Query_returns_null_for_missing_path()
    {
        Assert.Null(JwtTools.Query(HmacToken, "payload.does_not_exist"));
    }

    [Fact]
    public void TryQuery_propagates_FormatException_for_invalid_path()
    {
        Assert.Throws<FormatException>(() => JwtTools.TryQuery(HmacToken, "payload.bad[", out _));
    }

    [Fact]
    public void TryQuery_propagates_FormatException_for_invalid_token()
    {
        Assert.Throws<FormatException>(() => JwtTools.TryQuery("not.a.jwt", "payload.sub", out _));
    }
}
