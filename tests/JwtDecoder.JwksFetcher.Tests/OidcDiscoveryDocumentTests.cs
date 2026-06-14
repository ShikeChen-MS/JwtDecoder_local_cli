using System.Text;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class OidcDiscoveryDocumentTests
{
    private static byte[] Metadata(string issuer, string jwksUri)
    {
        return Encoding.UTF8.GetBytes(
            $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{jwksUri}\",\"response_types_supported\":[\"code\"]}}");
    }

    [Fact]
    public void Parse_HappyPath()
    {
        var bytes = Metadata("https://example.com", "https://example.com/.well-known/jwks.json");
        var result = OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com"));

        Assert.Equal(new Uri("https://example.com/.well-known/jwks.json"), result.JwksUri);
        Assert.False(result.CrossHostJwksUri);
    }

    [Theory]
    [InlineData("https://example.com",  "https://example.com")]
    [InlineData("https://example.com/", "https://example.com")]
    [InlineData("https://example.com",  "https://example.com/")]
    [InlineData("https://example.com:443", "https://example.com")]
    [InlineData("https://EXAMPLE.com",  "https://example.com")]
    [InlineData("https://example.com/realms/foo",  "https://example.com/realms/foo")]
    [InlineData("https://example.com/realms/foo/", "https://example.com/realms/foo")]
    public void Parse_NormalizesIssuerComparison(string metadataIssuer, string requestedIssuer)
    {
        var bytes = Metadata(metadataIssuer, "https://example.com/keys");
        var result = OidcDiscoveryDocument.Parse(bytes, new Uri(requestedIssuer));
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_RejectsIssuerMismatch()
    {
        var bytes = Metadata("https://attacker.example", "https://example.com/keys");
        var ex = Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
        Assert.Contains("issuer mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_FlagsCrossHostJwksUri()
    {
        var bytes = Metadata(
            "https://accounts.google.com",
            "https://www.googleapis.com/oauth2/v3/certs");
        var result = OidcDiscoveryDocument.Parse(bytes, new Uri("https://accounts.google.com"));

        Assert.True(result.CrossHostJwksUri);
        Assert.Equal("www.googleapis.com", result.JwksUri.Host);
    }

    [Fact]
    public void Parse_RejectsMissingIssuer()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"jwks_uri\":\"https://example.com/k\"}");
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsMissingJwksUri()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"issuer\":\"https://example.com\"}");
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsHttpJwksUri()
    {
        var bytes = Metadata("https://example.com", "http://example.com/keys");
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsDuplicateKeys()
    {
        var bytes = Encoding.UTF8.GetBytes(
            "{\"issuer\":\"https://example.com\",\"issuer\":\"https://other.com\",\"jwks_uri\":\"https://example.com/k\"}");
        var ex = Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
        Assert.Contains("duplicate", ex.Message);
    }

    [Fact]
    public void Parse_RejectsOversized()
    {
        var huge = new byte[OidcDiscoveryDocument.MaxMetadataBytes + 1];
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(huge, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsEmpty()
    {
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(ReadOnlySpan<byte>.Empty, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsInvalidJson()
    {
        var bytes = Encoding.UTF8.GetBytes("not json");
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
    }

    [Fact]
    public void Parse_RejectsRootNotObject()
    {
        var bytes = Encoding.UTF8.GetBytes("[]");
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.Parse(bytes, new Uri("https://example.com")));
    }

    [Theory]
    [InlineData("https://example.com",                "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/",               "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/realms/foo",     "https://example.com/realms/foo/.well-known/openid-configuration")]
    [InlineData("https://example.com/realms/foo/",    "https://example.com/realms/foo/.well-known/openid-configuration")]
    public void BuildDiscoveryUrl_FollowsOidcSpec(string issuer, string expected)
    {
        var built = OidcDiscoveryDocument.BuildDiscoveryUrl(new Uri(issuer));
        Assert.Equal(expected, built.ToString());
    }

    [Fact]
    public void BuildDiscoveryUrl_RejectsAlreadyWellKnown()
    {
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.BuildDiscoveryUrl(
                new Uri("https://example.com/.well-known/openid-configuration")));
    }

    [Fact]
    public void BuildDiscoveryUrl_RejectsHttp()
    {
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.BuildDiscoveryUrl(new Uri("http://example.com/")));
    }

    [Fact]
    public void CanonicalIssuerString_NormalizesPortHostSlash()
    {
        Assert.Equal(
            "https://example.com",
            OidcDiscoveryDocument.CanonicalIssuerString(new Uri("https://EXAMPLE.com/")));
        Assert.Equal(
            "https://example.com",
            OidcDiscoveryDocument.CanonicalIssuerString(new Uri("https://example.com:443")));
        Assert.Equal(
            "https://example.com/realms/foo",
            OidcDiscoveryDocument.CanonicalIssuerString(new Uri("https://Example.COM/realms/foo/")));
    }
}
