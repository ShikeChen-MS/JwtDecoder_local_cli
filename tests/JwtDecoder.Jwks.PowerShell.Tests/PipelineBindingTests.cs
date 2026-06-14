using System.Security.Cryptography;
using Xunit;

namespace JwtDecoder.Jwks.PowerShell.Tests;

/// <summary>
/// Verifies the single additive change to the offline <c>JwtDecoder</c> module:
/// <c>ValueFromPipelineByPropertyName = true</c> on
/// <c>Test-JsonWebTokenSignature -PublicKey</c>. The change must:
/// <list type="bullet">
/// <item>Not break the existing direct‑bind form.</item>
/// <item>Bind <c>.PublicKey</c> from a piped <see cref="JsonWebKey"/>.</item>
/// <item>Type-check (a wrong-typed <c>.PublicKey</c> property must fail, not silently fall through).</item>
/// </list>
/// </summary>
public class PipelineBindingTests
{
    [Fact]
    public void DirectBind_StillWorks_ForRsa()
    {
        var (token, jwksPath, _) = RunspaceHelpers.MakeSignedRsaPair();
        try
        {
            using var rsa = RSA.Create();
            // Load the public key from the JWKS we just wrote so it matches the signed token.
            // Simplest: use Get-JsonWebKey to get the PEM, then ImportFromPem here.
            var (rs1, ps1) = RunspaceHelpers.CreateLoaded();
            using (rs1)
            using (ps1)
            {
                ps1.AddCommand("Get-JsonWebKey")
                   .AddParameter("JwksFile", jwksPath)
                   .AddParameter("Token", token);
                var jwk = (JsonWebKey)ps1.Invoke()[0].BaseObject;
                rsa.ImportFromPem(jwk.Pem);
                jwk.Dispose();
            }

            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                ps.AddCommand("Test-JsonWebTokenSignature")
                  .AddParameter("Token", token)
                  .AddParameter("PublicKey", rsa);
                var output = ps.Invoke();
                Assert.False(ps.HadErrors);
                Assert.Single(output);
                bool isValid = (bool)output[0].Properties["IsValid"].Value;
                Assert.True(isValid, "direct-bind PublicKey must verify the signed JWT");
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void PipelineBind_FromGetJsonWebKey_VerifiesSignature()
    {
        var (token, jwksPath, _) = RunspaceHelpers.MakeSignedRsaPair();
        try
        {
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                // The crux of Phase 5: pipeline binding via .PublicKey property name.
                string script = $@"
                    $jwk = Get-JsonWebKey -JwksFile '{jwksPath.Replace("'", "''")}' -Token '{token}'
                    try {{ $jwk | Test-JsonWebTokenSignature -Token '{token}' }} finally {{ $jwk.Dispose() }}
                ";
                ps.AddScript(script);
                var output = ps.Invoke();
                Assert.False(ps.HadErrors,
                    "pipeline form must succeed; errors: " +
                    string.Join("; ", ps.Streams.Error.Select(e => e.ToString())));
                Assert.Single(output);
                bool isValid = (bool)output[0].Properties["IsValid"].Value;
                Assert.True(isValid);
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void PipelineBind_OneLinerWithoutExplicitDispose_StillBinds()
    {
        // The pipeline-flow form: $jwk is short-lived; verifies inside ProcessRecord.
        var (token, jwksPath, _) = RunspaceHelpers.MakeSignedRsaPair();
        try
        {
            var (rs, ps) = RunspaceHelpers.CreateLoaded();
            using (rs)
            using (ps)
            {
                string script = $@"
                    Get-JsonWebKey -JwksFile '{jwksPath.Replace("'", "''")}' -Token '{token}' |
                        Test-JsonWebTokenSignature -Token '{token}'
                ";
                ps.AddScript(script);
                var output = ps.Invoke();
                Assert.False(ps.HadErrors);
                Assert.Single(output);
                bool isValid = (bool)output[0].Properties["IsValid"].Value;
                Assert.True(isValid);
            }
        }
        finally { File.Delete(jwksPath); }
    }

    [Fact]
    public void PipelineBind_FromObjectWithWrongPublicKeyType_FailsCleanly()
    {
        // A PSCustomObject whose .PublicKey is a string must NOT silently fall through.
        var (token, _, _) = RunspaceHelpers.MakeSignedRsaPair();
        var (rs, ps) = RunspaceHelpers.CreateLoaded();
        using (rs)
        using (ps)
        {
            string script = $@"
                [pscustomobject]@{{ PublicKey = 'not-a-key' }} |
                    Test-JsonWebTokenSignature -Token '{token}'
            ";
            ps.AddScript(script);
            try
            {
                var output = ps.Invoke();
                // If we got here without exception, ensure ps.HadErrors is true.
                Assert.True(ps.HadErrors, "binding a non-AsymmetricAlgorithm to -PublicKey must surface an error");
            }
            catch (System.Management.Automation.RuntimeException)
            {
                // Acceptable outcome: a binding/runtime exception was raised.
            }
        }
    }
}
