using System.Security.Cryptography;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class JwkSelectorTests
{
    [Fact]
    public void Select_PicksByKid()
    {
        using var r1 = RSA.Create(2048);
        using var r2 = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.RsaJwk(r1, kid: "k1"),
            TestFixtures.RsaJwk(r2, kid: "k2")));

        var result = JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: "k2");

        Assert.Equal("k2", result.Selected.Kid);
        Assert.Null(result.Warning);
    }

    [Fact]
    public void Select_PicksSingleWhenJwtHasNoKid_AndWarns()
    {
        using var r1 = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(r1, kid: "k1")));

        var result = JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: null);

        Assert.Equal("k1", result.Selected.Kid);
        Assert.NotNull(result.Warning);
    }

    [Fact]
    public void Select_RejectsAmbiguousNoKid()
    {
        using var r1 = RSA.Create(2048);
        using var r2 = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.RsaJwk(r1, kid: "k1"),
            TestFixtures.RsaJwk(r2, kid: "k2")));

        var ex = Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: null));
        Assert.Contains("ambiguous", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Select_RejectsUnknownKid()
    {
        using var r1 = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(r1, kid: "k1")));

        Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: "nope"));
    }

    [Fact]
    public void Select_RejectsWhenJwksKtyMismatchesAlg()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.EcJwk(ec, crv: "P-256", kid: "e1")));

        Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: "e1"));
    }

    [Theory]
    [InlineData("ES256", "P-256")]
    [InlineData("ES384", "P-384")]
    [InlineData("ES512", "P-521")]
    public void Select_BindsEcAlgToCurve(string alg, string crv)
    {
        var bclCurve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ec = ECDsa.Create(bclCurve);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.EcJwk(ec, crv: crv, kid: "e1", alg: alg)));

        var result = JwkSelector.Select(keys, jwtAlg: alg, jwtKid: "e1");
        Assert.Equal(crv, result.Selected.Crv);
    }

    [Fact]
    public void Select_RefusesMismatchedCurve()
    {
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.EcJwk(p256, crv: "P-256", kid: "a"),
            TestFixtures.EcJwk(p384, crv: "P-384", kid: "b")));

        // alg ES384 (curve P-384) must NOT pick the P-256 key.
        var result = JwkSelector.Select(keys, jwtAlg: "ES384", jwtKid: "b");
        Assert.Equal("b", result.Selected.Kid);
        Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "ES384", jwtKid: "a"));
    }

    [Fact]
    public void Select_RefusesJwkAlgConflict()
    {
        using var rsa = RSA.Create(2048);
        // JWK declares RS512 but JWT requests RS256.
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.RsaJwk(rsa, kid: "k1", alg: "RS512")));

        // alg-filter excludes the only candidate, then "no match" is the failure.
        var ex = Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: "k1"));
        Assert.Contains("RS256", ex.Message);
    }

    [Fact]
    public void Select_RefusesUnsupportedJwtAlg()
    {
        using var rsa = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa)));

        Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "HS256", jwtKid: null));
    }

    [Fact]
    public void Select_DuplicateKidWithinCandidates_IsRefused()
    {
        // Both keys share kid='dup' and both match alg RS256 → ambiguous.
        using var r1 = RSA.Create(2048);
        using var r2 = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.RsaJwk(r1, kid: "dup", alg: "RS256"),
            TestFixtures.RsaJwk(r2, kid: "dup", alg: "RS256")));

        var ex = Assert.Throws<InvalidDataException>(() =>
            JwkSelector.Select(keys, jwtAlg: "RS256", jwtKid: "dup"));
        Assert.Contains("Multiple", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Select_DuplicateKidAcrossDifferentAlgFamilies_IsAllowed()
    {
        // Rolling rotation: same kid, different alg → not ambiguous when filtered
        // by alg. The candidate-scope dup-kid rule lets this through.
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(
            TestFixtures.RsaJwk(rsa, kid: "shared", alg: "RS256"),
            TestFixtures.EcJwk(ec, crv: "P-256", kid: "shared", alg: "ES256")));

        var rsaResult = JwkSelector.Select(keys, "RS256", "shared");
        var ecResult  = JwkSelector.Select(keys, "ES256", "shared");
        Assert.Equal("RSA", rsaResult.Selected.Kty);
        Assert.Equal("EC",  ecResult.Selected.Kty);
    }

    [Fact]
    public void Select_NullArgs_Throw()
    {
        using var rsa = RSA.Create(2048);
        var keys = JwksDocument.Parse(TestFixtures.JwksOf(TestFixtures.RsaJwk(rsa)));
        Assert.Throws<ArgumentNullException>(() => JwkSelector.Select(null!, "RS256", null));
        Assert.Throws<ArgumentNullException>(() => JwkSelector.Select(keys, null!, null));
    }
}
