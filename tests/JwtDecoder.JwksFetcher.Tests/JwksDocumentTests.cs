using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class JwksDocumentTests
{
    [Fact]
    public void Parse_RoundTripsRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var bytes = TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa, kid: "k1"));

        var keys = JwksDocument.Parse(bytes);

        Assert.Single(keys);
        Assert.Equal("RSA", keys[0].Kty);
        Assert.Equal("k1", keys[0].Kid);
        Assert.Equal("RS256", keys[0].Alg);
        Assert.NotNull(keys[0].N);
        Assert.NotNull(keys[0].E);
    }

    [Fact]
    public void Parse_RoundTripsEcKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = TestFixtures.JwksOf(TestFixtures.EcJwk(ec, crv: "P-256", kid: "e1", alg: "ES256"));

        var keys = JwksDocument.Parse(bytes);

        Assert.Single(keys);
        Assert.Equal("EC", keys[0].Kty);
        Assert.Equal("P-256", keys[0].Crv);
        Assert.Equal("e1", keys[0].Kid);
    }

    [Fact]
    public void Parse_RejectsOversizedDocument()
    {
        var huge = new byte[JwksDocument.MaxJwksBytes + 1];
        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(huge));
        Assert.Contains("maximum size", ex.Message);
    }

    [Fact]
    public void Parse_RejectsEmptyDocument()
    {
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Parse_RejectsMissingKeysArray()
    {
        var json = TestFixtures.Utf8("{\"not_keys\":[]}");
        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
        Assert.Contains("'keys'", ex.Message);
    }

    [Fact]
    public void Parse_RejectsKeysNotArray()
    {
        var json = TestFixtures.Utf8("{\"keys\":{}}");
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsEmptyKeysArray()
    {
        var json = TestFixtures.Utf8("{\"keys\":[]}");
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsTopLevelDuplicateKeys()
    {
        var json = TestFixtures.Utf8("{\"keys\":[],\"keys\":[]}");
        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
        Assert.Contains("duplicate", ex.Message);
    }

    [Fact]
    public void Parse_RejectsDuplicateKeysInsideJwk()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        string n = TestFixtures.Base64Url(p.Modulus!);
        string e = TestFixtures.Base64Url(p.Exponent!);
        var json = TestFixtures.Utf8(
            "{\"keys\":[{\"kty\":\"RSA\",\"kty\":\"EC\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}]}");
        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
        Assert.Contains("duplicate", ex.Message);
    }

    [Fact]
    public void Parse_RejectsKtyOct()
    {
        var json = TestFixtures.Utf8("{\"keys\":[{\"kty\":\"oct\",\"k\":\"ZmFrZQ\"}]}");
        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
        Assert.Contains("kty=oct", ex.Message);
    }

    [Fact]
    public void Parse_RejectsUnknownKty()
    {
        var json = TestFixtures.Utf8("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"abc\"}]}");
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Theory]
    [InlineData("x5u")]
    [InlineData("jku")]
    public void Parse_RejectsRemoteReferenceFields(string field)
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk[field] = "https://example.com/keys";
        var bytes = TestFixtures.JwksOf(jwk);

        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
        Assert.Contains(field, ex.Message);
    }

    [Fact]
    public void Parse_IgnoresX5c()
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk["x5c"] = new[] { "MIIDXTCCAkWgAwIBAgIJAKxxxx" };
        var bytes = TestFixtures.JwksOf(jwk);

        var keys = JwksDocument.Parse(bytes);
        Assert.Single(keys);
    }

    [Theory]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("qi")]
    public void Parse_RejectsRsaPrivateComponents(string field)
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk[field] = "AAAA";
        var bytes = TestFixtures.JwksOf(jwk);

        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
        Assert.Contains("private", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_RejectsEcPrivateComponent()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = TestFixtures.EcJwk(ec, "P-256");
        jwk["d"] = "AAAA";
        var bytes = TestFixtures.JwksOf(jwk);

        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
    }

    [Fact]
    public void Parse_RejectsTooSmallRsaModulus()
    {
        // 1024-bit RSA. The JwksDocument min is 2048.
        using var rsa = RSA.Create(1024);
        var bytes = TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa));

        var ex = Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
        Assert.Contains("minimum", ex.Message);
    }

    [Fact]
    public void Parse_RejectsRsaExponentLessThan3()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var json = TestFixtures.Utf8(
            "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" + TestFixtures.Base64Url(p.Modulus!) +
            "\",\"e\":\"AQ\"}]}"); // 0x01 -> base64url "AQ"
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsEvenRsaExponent()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var json = TestFixtures.Utf8(
            "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" + TestFixtures.Base64Url(p.Modulus!) +
            "\",\"e\":\"BA\"}]}"); // 0x04 -> "BA"
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsMismatchedEcPointLength()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = TestFixtures.EcJwk(ec, "P-256");
        // Forge: declare P-384 but pass P-256 coordinates (32 bytes != 48).
        jwk["crv"] = "P-384";
        var bytes = TestFixtures.JwksOf(jwk);
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
    }

    [Fact]
    public void Parse_RejectsUseEnc()
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk["use"] = "enc";
        var bytes = TestFixtures.JwksOf(jwk);
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
    }

    [Fact]
    public void Parse_AcceptsUseSig()
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk["use"] = "sig";
        var bytes = TestFixtures.JwksOf(jwk);
        var keys = JwksDocument.Parse(bytes);
        Assert.Single(keys);
        Assert.Equal("sig", keys[0].Use);
    }

    [Fact]
    public void Parse_RejectsKeyOpsWithoutVerify()
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk["key_ops"] = new[] { "encrypt", "decrypt" };
        var bytes = TestFixtures.JwksOf(jwk);
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(bytes));
    }

    [Fact]
    public void Parse_AcceptsKeyOpsContainingVerify()
    {
        using var rsa = RSA.Create(2048);
        var jwk = TestFixtures.RsaJwk(rsa);
        jwk["key_ops"] = new[] { "verify", "wrapKey" };
        var bytes = TestFixtures.JwksOf(jwk);
        var keys = JwksDocument.Parse(bytes);
        Assert.NotNull(keys[0].KeyOps);
        Assert.Contains("verify", keys[0].KeyOps!);
    }

    [Fact]
    public void Parse_RejectsJsonComments()
    {
        var json = Encoding.UTF8.GetBytes("// hi\n{\"keys\":[]}");
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsTrailingComma()
    {
        var json = TestFixtures.Utf8("{\"keys\":[],}");
        Assert.Throws<InvalidDataException>(() => JwksDocument.Parse(json));
    }

    [Fact]
    public void Parse_AllowsMultipleDistinctKeys()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var bytes = TestFixtures.JwksOf(
            TestFixtures.RsaJwk(rsa1, kid: "k1"),
            TestFixtures.RsaJwk(rsa2, kid: "k2"));
        var keys = JwksDocument.Parse(bytes);
        Assert.Equal(2, keys.Count);
        Assert.Equal(new[] { "k1", "k2" }, keys.Select(k => k.Kid));
    }
}
