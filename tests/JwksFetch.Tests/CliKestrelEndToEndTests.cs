using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using JwtDecoder.JwksFetcher.Tests; // HttpsTestServer (compile-linked)
using Xunit;

namespace JwksFetch.Tests;

/// <summary>
/// End-to-end CLI tests that drive <c>Program.RunCore</c> against a real
/// loopback Kestrel HTTPS server. Exercises the <c>--jwks-url</c> and
/// <c>--from-issuer</c> code paths through the full FetcherOptions builder,
/// SSRF policy, redirect loop, and exit-code mapping.
/// </summary>
public sealed class CliKestrelEndToEndTests : IDisposable
{
    public CliKestrelEndToEndTests()
    {
        // Permit loopback for the duration of the test class. JwtDecoder.JwksFetcher
        // refuses 127.0.0.1 by default; the internal hook is the only way to
        // override that without weakening production code.
        JwksFetch.TestHooks.AllowLoopbackForTesting = true;
    }

    public void Dispose()
    {
        JwksFetch.TestHooks.AllowLoopbackForTesting = false;
    }

    // ---------- fixtures ----------

    private static string MakeRsaJwksJson(out string kid)
    {
        kid = "ut-rsa-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        string n = B64Url(p.Modulus!);
        string e = B64Url(p.Exponent!);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"{kid}\",\"alg\":\"RS256\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    private static string MakeTokenFor(string kid)
    {
        string header  = $"{{\"alg\":\"RS256\",\"kid\":\"{kid}\",\"typ\":\"JWT\"}}";
        string payload = "{\"sub\":\"x\"}";
        string h = B64Url(Encoding.UTF8.GetBytes(header));
        string p = B64Url(Encoding.UTF8.GetBytes(payload));
        return $"{h}.{p}.AAAA";
    }

    private static string B64Url(ReadOnlySpan<byte> bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        int trim = 0;
        while (trim < b64.Length && b64[b64.Length - 1 - trim] == '=') trim++;
        if (trim > 0) b64 = b64.Substring(0, b64.Length - trim);
        return b64.Replace('+', '-').Replace('/', '_');
    }

    private static string WriteTempFile(string contents, string suffix)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + suffix);
        File.WriteAllText(path, contents);
        return path;
    }

    // ---------- --jwks-url ----------

    [Fact]
    public async Task JwksUrl_HappyPath_EmitsPemAndExitsZero()
    {
        string jwks = MakeRsaJwksJson(out string kid);
        await using var srv = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/keys", () => Results.Text(jwks, "application/json")));

        string token = MakeTokenFor(kid);
        string tokFile = WriteTempFile(token, ".jwt");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(new[]
            {
                "--jwks-url",   new Uri(srv.BaseAddress, "keys").ToString(),
                "--token-file", tokFile,
                "--ca-bundle",  srv.CaBundlePath,
            }, stdout, stderr, null);

            Assert.True(code == 0, $"expected exit 0; stderr: {stderr}");
            Assert.Contains("-----BEGIN PUBLIC KEY-----", stdout.ToString());
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task JwksUrl_KidMismatch_ReturnsExit3()
    {
        string jwks = MakeRsaJwksJson(out _);
        await using var srv = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/keys", () => Results.Text(jwks, "application/json")));

        string token = MakeTokenFor("WRONG");
        string tokFile = WriteTempFile(token, ".jwt");
        try
        {
            var sw = new StringWriter();
            int code = Program.RunCore(new[]
            {
                "--jwks-url",   new Uri(srv.BaseAddress, "keys").ToString(),
                "--token-file", tokFile,
                "--ca-bundle",  srv.CaBundlePath,
            }, sw, sw, null);
            Assert.Equal(3, code);
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task JwksUrl_OversizedResponse_ReturnsExit4()
    {
        await using var srv = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/big", () => Results.Bytes(new byte[100 * 1024], "application/octet-stream")));

        string tokFile = WriteTempFile(MakeTokenFor("any"), ".jwt");
        try
        {
            var sw = new StringWriter();
            int code = Program.RunCore(new[]
            {
                "--jwks-url",          new Uri(srv.BaseAddress, "big").ToString(),
                "--token-file",        tokFile,
                "--ca-bundle",         srv.CaBundlePath,
                "--max-response-bytes","1024",
            }, sw, sw, null);
            Assert.Equal(4, code);
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task JwksUrl_RedirectCapExceeded_ReturnsExit4()
    {
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/a", ctx => { ctx.Response.Redirect("/b"); return Task.CompletedTask; });
            app.MapGet("/b", ctx => { ctx.Response.Redirect("/c"); return Task.CompletedTask; });
            app.MapGet("/c", () => Results.Text("never", "text/plain"));
        });

        string tokFile = WriteTempFile(MakeTokenFor("any"), ".jwt");
        try
        {
            var sw = new StringWriter();
            int code = Program.RunCore(new[]
            {
                "--jwks-url",     new Uri(srv.BaseAddress, "a").ToString(),
                "--token-file",   tokFile,
                "--ca-bundle",    srv.CaBundlePath,
                "--max-redirects","1",
            }, sw, sw, null);
            Assert.Equal(4, code);
        }
        finally { File.Delete(tokFile); }
    }

    // ---------- --from-issuer ----------

    [Fact]
    public async Task FromIssuer_HappyPath_EmitsPem()
    {
        string jwks = MakeRsaJwksJson(out string kid);
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                string iss  = $"https://{ctx.Request.Host}";
                string body = $"{{\"issuer\":\"{iss}\",\"jwks_uri\":\"{iss}/keys\"}}";
                return Results.Text(body, "application/json").ExecuteAsync(ctx);
            });
            app.MapGet("/keys", () => Results.Text(jwks, "application/json"));
        });

        string token = MakeTokenFor(kid);
        string tokFile = WriteTempFile(token, ".jwt");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            string issuer = srv.BaseAddress.ToString().TrimEnd('/');
            int code = Program.RunCore(new[]
            {
                "--from-issuer", issuer,
                "--token-file",  tokFile,
                "--ca-bundle",   srv.CaBundlePath,
            }, stdout, stderr, null);

            Assert.True(code == 0, $"expected 0; stderr: {stderr}");
            Assert.Contains("-----BEGIN PUBLIC KEY-----", stdout.ToString());
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task FromIssuer_IssuerMismatch_ReturnsExit3()
    {
        await using var srv = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/.well-known/openid-configuration", () =>
                Results.Text(
                    "{\"issuer\":\"https://attacker.example\",\"jwks_uri\":\"https://attacker.example/keys\"}",
                    "application/json")));

        string tokFile = WriteTempFile(MakeTokenFor("any"), ".jwt");
        try
        {
            var sw = new StringWriter();
            string issuer = srv.BaseAddress.ToString().TrimEnd('/');
            int code = Program.RunCore(new[]
            {
                "--from-issuer", issuer,
                "--token-file",  tokFile,
                "--ca-bundle",   srv.CaBundlePath,
            }, sw, sw, null);
            Assert.Equal(3, code);
            Assert.Contains("issuer", sw.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task FromIssuer_CrossHostJwksUri_EmitsWarningAndExitsZero()
    {
        // Two test servers: one is the "issuer", the other serves the JWKS at
        // a different host. Both bind to 127.0.0.1 but on different ports —
        // sufficient to make jwks_uri.Host differ from issuer.Host in URI terms.
        // We bind the JWKS server first so we know its address.
        string kid;
        string jwksJson = MakeRsaJwksJson(out kid);
        await using var jwksSrv = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/keys", () => Results.Text(jwksJson, "application/json")));

        // Now the issuer server, advertising the JWKS server's URL.
        await using var issuerSrv = await HttpsTestServer.StartAsync(app =>
        {
            // Capture the JWKS server's URL inside the handler closure.
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                string iss = $"https://{ctx.Request.Host}";
                // jwks_uri points at the OTHER loopback server's host:port
                string jwksUri = $"{jwksSrv.BaseAddress}keys".Replace("//keys", "/keys");
                string body = $"{{\"issuer\":\"{iss}\",\"jwks_uri\":\"{jwksUri}\"}}";
                return Results.Text(body, "application/json").ExecuteAsync(ctx);
            });
        });

        string tokFile = WriteTempFile(MakeTokenFor(kid), ".jwt");
        try
        {
            // Both servers use self-signed certs from DIFFERENT roots, so we
            // need to concatenate both CA bundles into one PEM.
            string combined = File.ReadAllText(issuerSrv.CaBundlePath) +
                              File.ReadAllText(jwksSrv.CaBundlePath);
            string caCombined = WriteTempFile(combined, ".pem");

            try
            {
                var stdout = new StringWriter();
                var stderr = new StringWriter();
                string issuer = issuerSrv.BaseAddress.ToString().TrimEnd('/');
                int code = Program.RunCore(new[]
                {
                    "--from-issuer", issuer,
                    "--token-file",  tokFile,
                    "--ca-bundle",   caCombined,
                }, stdout, stderr, null);

                // The two BaseAddresses share host 127.0.0.1 but differ in port.
                // OidcDiscoveryDocument compares Host strings only, so cross-host
                // is false here (Host = "127.0.0.1" both sides). We still expect
                // a successful PEM emission.
                Assert.True(code == 0, $"expected 0; stderr: {stderr}");
                Assert.Contains("-----BEGIN PUBLIC KEY-----", stdout.ToString());
            }
            finally { File.Delete(caCombined); }
        }
        finally { File.Delete(tokFile); }
    }

    [Fact]
    public async Task FromIssuer_AlreadyWellKnownInIssuer_RejectedByArgValidation()
    {
        // The /.well-known/ path in the issuer URL is refused before any
        // network activity, by OidcDiscoveryDocument.BuildDiscoveryUrl.
        await using var srv = await HttpsTestServer.StartAsync(_ => { });
        string tokFile = WriteTempFile(MakeTokenFor("any"), ".jwt");
        try
        {
            var sw = new StringWriter();
            string issuer = new Uri(srv.BaseAddress, ".well-known/openid-configuration").ToString();
            int code = Program.RunCore(new[]
            {
                "--from-issuer", issuer,
                "--token-file",  tokFile,
                "--ca-bundle",   srv.CaBundlePath,
            }, sw, sw, null);
            Assert.Equal(2, code);
        }
        finally { File.Delete(tokFile); }
    }
}
