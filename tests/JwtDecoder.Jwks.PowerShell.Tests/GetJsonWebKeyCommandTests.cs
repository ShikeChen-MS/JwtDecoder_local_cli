using System.Security.Cryptography;
using Xunit;

namespace JwtDecoder.Jwks.PowerShell.Tests;

/// <summary>
/// In-process tests of <c>Get-JsonWebKey</c> using a real PowerShell runspace
/// hosted by Microsoft.PowerShell.SDK.
/// </summary>
public class GetJsonWebKeyCommandTests
{
    [Fact]
    public void GetJsonWebKey_JwksFile_RoundTripsRsa()
    {
        string kid;
        string jwksPath = RunspaceHelpers.MakeRsaJwksFile(out kid);
        try
        {
            string token = RunspaceHelpers.MakeUnsignedToken(
                $"{{\"alg\":\"RS256\",\"kid\":\"{kid}\"}}",
                "{\"sub\":\"x\"}");

            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Get-JsonWebKey")
                  .AddParameter("JwksFile", jwksPath)
                  .AddParameter("Token", token);

                var output = ps.Invoke();
                Assert.False(ps.HadErrors, "no errors expected");
                Assert.Single(output);
                var jwk = Assert.IsType<JsonWebKey>(output[0].BaseObject);
                Assert.Equal("RSA", jwk.Kty);
                Assert.Equal(kid, jwk.Kid);
                Assert.Equal("RS256", jwk.Algorithm);
                Assert.Contains("BEGIN PUBLIC KEY", jwk.Pem);
                Assert.IsAssignableFrom<RSA>(jwk.PublicKey);
                jwk.Dispose();
                Assert.Null(jwk.PublicKey); // disposed -> null
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void GetJsonWebKey_RejectsBothTokenAndPath()
    {
        string kid;
        string jwksPath = RunspaceHelpers.MakeRsaJwksFile(out kid);
        try
        {
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Get-JsonWebKey")
                  .AddParameter("JwksFile", jwksPath)
                  .AddParameter("Token", "x.y.z")
                  .AddParameter("Path", "z.jwt");

                Assert.Throws<System.Management.Automation.CmdletInvocationException>(() => ps.Invoke());
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void GetJsonWebKey_RejectsMissingTokenAndPath()
    {
        string kid;
        string jwksPath = RunspaceHelpers.MakeRsaJwksFile(out kid);
        try
        {
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Get-JsonWebKey")
                  .AddParameter("JwksFile", jwksPath);

                Assert.Throws<System.Management.Automation.CmdletInvocationException>(() => ps.Invoke());
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void GetJsonWebKey_KidMismatch_Throws()
    {
        string kid;
        string jwksPath = RunspaceHelpers.MakeRsaJwksFile(out kid);
        try
        {
            string token = RunspaceHelpers.MakeUnsignedToken(
                "{\"alg\":\"RS256\",\"kid\":\"WRONG\"}", "{}");
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Get-JsonWebKey")
                  .AddParameter("JwksFile", jwksPath)
                  .AddParameter("Token", token);

                Assert.Throws<System.Management.Automation.CmdletInvocationException>(() => ps.Invoke());
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void GetJsonWebKey_ProxyAndUseSystemProxy_AreMutuallyExclusive()
    {
        string kid;
        string jwksPath = RunspaceHelpers.MakeRsaJwksFile(out kid);
        try
        {
            string token = RunspaceHelpers.MakeUnsignedToken(
                $"{{\"alg\":\"RS256\",\"kid\":\"{kid}\"}}", "{}");
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Get-JsonWebKey")
                  .AddParameter("JwksFile", jwksPath)
                  .AddParameter("Token", token)
                  .AddParameter("Proxy", new Uri("http://corp.example:8080"))
                  .AddParameter("UseSystemProxy", true);

                Assert.Throws<System.Management.Automation.CmdletInvocationException>(() => ps.Invoke());
            }
        }
        finally { File.Delete(jwksPath); }
    }
}
