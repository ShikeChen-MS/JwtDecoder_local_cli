using System.Security.Cryptography;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class JwkToPemTests
{
    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void Rsa_RoundTripsThroughPem(int keySize)
    {
        using var rsa = RSA.Create(keySize);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa)));

        string pem = JwkToPem.ToPublicKeyPem(keys[0]);
        Assert.Contains("BEGIN PUBLIC KEY", pem);

        using var rsa2 = RSA.Create();
        rsa2.ImportFromPem(pem);
        var pOriginal = rsa.ExportParameters(false);
        var pRoundTrip = rsa2.ExportParameters(false);
        Assert.Equal(pOriginal.Modulus, pRoundTrip.Modulus);
        Assert.Equal(pOriginal.Exponent, pRoundTrip.Exponent);
    }

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void Ec_RoundTripsThroughPem(string crv)
    {
        var bclCurve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ec = ECDsa.Create(bclCurve);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.EcJwk(ec, crv: crv)));

        string pem = JwkToPem.ToPublicKeyPem(keys[0]);
        Assert.Contains("BEGIN PUBLIC KEY", pem);

        using var ec2 = ECDsa.Create();
        ec2.ImportFromPem(pem);
        var pOriginal = ec.ExportParameters(false);
        var pRoundTrip = ec2.ExportParameters(false);
        Assert.Equal(pOriginal.Q.X, pRoundTrip.Q.X);
        Assert.Equal(pOriginal.Q.Y, pRoundTrip.Q.Y);
    }

    [Fact]
    public void RoundTripPem_LoadsViaCoreKeyLoaderEquivalent()
    {
        // Defensive: the JwtDecoder.Core KeyLoader expects either "PUBLIC KEY" or
        // "RSA PUBLIC KEY" labels for RSA; our SPKI export uses "PUBLIC KEY".
        using var rsa = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa)));
        string pem = JwkToPem.ToPublicKeyPem(keys[0]);

        // SubjectPublicKeyInfo PEM label is exactly "PUBLIC KEY" — what KeyLoader
        // accepts. This guards against an accidental future switch to
        // ExportRSAPublicKeyPem ("RSA PUBLIC KEY" label / PKCS#1 body), which
        // some PEM consumers don't accept.
        Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
        Assert.DoesNotContain("BEGIN RSA PUBLIC KEY", pem);
    }

    [Fact]
    public void ToPublicKeyPem_NullJwk_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => JwkToPem.ToPublicKeyPem(null!));
    }
}
