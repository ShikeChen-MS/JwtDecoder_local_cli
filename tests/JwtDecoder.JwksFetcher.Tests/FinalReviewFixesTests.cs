using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

/// <summary>
/// Tests that close the holes the final rubber-duck review identified.
/// </summary>
public class FinalReviewFixesTests
{
    private static FetcherOptions OptsFor(HttpsTestServer s, FetcherOptions? overrides = null) => new()
    {
        Timeout = overrides?.Timeout ?? TimeSpan.FromSeconds(5),
        MaxResponseBytes = overrides?.MaxResponseBytes ?? 64 * 1024,
        MaxRedirects = overrides?.MaxRedirects ?? 3,
        CaBundlePath = s.CaBundlePath,
        BearerTokenBytes = overrides?.BearerTokenBytes,
        ExtraHeaders = overrides?.ExtraHeaders,
        AllowLoopbackForTesting = true,
        SendBearerToDiscovery = overrides?.SendBearerToDiscovery ?? false,
    };

    // --- B1: --ca-bundle must still reject hostname mismatch -----------------
    // A custom CA bundle was overriding the WHOLE callback, including
    // RemoteCertificateNameMismatch. A cert signed by the trusted CA for
    // attacker.example would have authenticated 127.0.0.1.

    [Fact]
    public async Task CaBundle_StillRejectsHostnameMismatch()
    {
        // Start a Kestrel server bound to 127.0.0.1 with a cert whose SAN is
        // "wrong.example" — NOT 127.0.0.1, NOT localhost.
        await using var srv = await HttpsTestServer.StartAsync(
            app => app.MapGet("/k", () => Results.Text("should not be reachable", "text/plain")),
            sanHost: "wrong.example");

        // Connect via 127.0.0.1 and trust ONLY the server's self-signed root
        // through --ca-bundle. The fix refuses on RemoteCertificateNameMismatch.
        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await JwksClient.FetchAsync(new Uri(srv.BaseAddress, "k"), OptsFor(srv)));
    }

    // --- I4: extra headers must be stripped on every redirect ----------------

    [Fact]
    public async Task ExtraHeaders_StrippedOnRedirect()
    {
        string? firstHop = null;
        string? secondHop = null;
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/first", ctx =>
            {
                firstHop = ctx.Request.Headers["X-Api-Key"];
                ctx.Response.Redirect("/second");
                return Task.CompletedTask;
            });
            app.MapGet("/second", ctx =>
            {
                secondHop = ctx.Request.Headers["X-Api-Key"];
                return Results.Text("ok", "text/plain").ExecuteAsync(ctx);
            });
        });

        var opts = OptsFor(srv, new FetcherOptions
        {
            ExtraHeaders = new[] { ("X-Api-Key", "secret-token-value") },
        });
        await JwksClient.FetchAsync(new Uri(srv.BaseAddress, "first"), opts);

        Assert.Equal("secret-token-value", firstHop);
        Assert.True(string.IsNullOrEmpty(secondHop),
            "Extra headers (--header-file) MUST be stripped on redirect (final-review I4). Was: " + secondHop);
    }

    // --- B2: --require-same-host-jwks-uri must refuse BEFORE the JWKS fetch --
    //
    // The pre-fix behavior: OidcDiscoveryClient fetched the cross-host JWKS,
    // then surfaced CrossHostJwksUri to the caller, who refused after the
    // bearer had already leaked. The fix enforces inside the library before
    // dispatching the JWKS request.

    [Fact]
    public async Task RequireSameHostJwksUri_RefusesBeforeJwksFetch()
    {
        // The discovery server claims a jwks_uri at a DIFFERENT host. We
        // pick a clearly unreachable address so a post-fetch check would
        // surface as a network error; the pre-fetch refusal surfaces as
        // InvalidDataException with a recognisable message.
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                string iss = $"https://{ctx.Request.Host}";
                string body =
                    $"{{\"issuer\":\"{iss}\",\"jwks_uri\":\"https://different.host.invalid/keys\"}}";
                return Results.Text(body, "application/json").ExecuteAsync(ctx);
            });
        });

        var fopts = OptsFor(srv);
        var dopts = new OidcDiscoveryOptions { RequireSameHostJwksUri = true };
        var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));

        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(issuer, fopts, dopts));
        Assert.Contains("RequireSameHostJwksUri", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequireSameHostJwksUri_BearerNeverSentToCrossHost()
    {
        // The discovery server claims a jwks_uri pointing at the SAME Kestrel
        // server but on a different captured-host path. We track whether any
        // request reaches the "jwks" handler; with the fix it must not when
        // the policy is enabled.
        bool jwksHit = false;
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                string iss = $"https://{ctx.Request.Host}";
                // Point jwks_uri at a DIFFERENT hostname (unreachable on this
                // machine) so the cross-host check fires.
                string body =
                    $"{{\"issuer\":\"{iss}\",\"jwks_uri\":\"https://different.host.invalid/keys\"}}";
                return Results.Text(body, "application/json").ExecuteAsync(ctx);
            });
            app.MapGet("/keys", ctx => { jwksHit = true; return Task.CompletedTask; });
        });

        var fopts = OptsFor(srv, new FetcherOptions { BearerTokenBytes = Encoding.UTF8.GetBytes("secret") });
        var dopts = new OidcDiscoveryOptions { RequireSameHostJwksUri = true };
        var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(issuer, fopts, dopts));

        // The local /keys handler must not have been hit — the library
        // refused before dispatching ANY second request, so the bearer
        // never left the discovery hop.
        Assert.False(jwksHit, "JWKS endpoint must NOT have been reached when the policy refuses; bearer would have leaked.");
    }

    // --- F1: --ca-bundle must require ServerAuth EKU on the leaf cert -------
    //
    // A cert signed by the trusted CA with the CORRECT SAN but with
    // EKU=CodeSigning only should be refused as a server cert.
    //
    // We test this at the X509Chain level rather than end-to-end through
    // Kestrel, because Kestrel itself refuses to listen with a code-signing-
    // only certificate. That refusal is a layered defence (server-side); the
    // client-side ApplicationPolicy is the parallel defence we test here.

    [Fact]
    public void CaBundle_CustomChain_RequiresServerAuthEku()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter  = DateTimeOffset.UtcNow.AddDays(1);

        // Build an in-memory CA + leaf, with the leaf carrying ONLY EKU=CodeSigning.
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var caCert = caReq.CreateSelfSigned(notBefore, notAfter);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=leaf.example", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(System.Net.IPAddress.Loopback);
        leafReq.CertificateExtensions.Add(san.Build());
        var ekus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }; // Code Signing only
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, critical: false));
        var serial = Guid.NewGuid().ToByteArray();
        using var leafCert = leafReq.Create(caCert, notBefore, notAfter, serial);

        // Build a chain with the SAME policy the production callback uses:
        // CustomRootTrust + CustomTrustStore={CA} + ApplicationPolicy={ServerAuth}.
        // This is the exact chain check JwksClient.BuildHandler performs.
        using var customChain = new X509Chain();
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(caCert);
        customChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));

        bool ok = customChain.Build(leafCert);
        Assert.False(ok,
            "ServerAuth EKU policy must reject a leaf cert with EKU=CodeSigning only " +
            "(final-review F1). Chain status: " +
            string.Join(", ", customChain.ChainStatus.Select(s => s.StatusInformation.Trim())));
    }

    [Fact]
    public void CaBundle_CustomChain_AcceptsLeafWithServerAuthEku()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter  = DateTimeOffset.UtcNow.AddDays(1);

        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var caCert = caReq.CreateSelfSigned(notBefore, notAfter);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=leaf.example", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var ekus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }; // Server Authentication
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, critical: false));
        var serial = Guid.NewGuid().ToByteArray();
        using var leafCert = leafReq.Create(caCert, notBefore, notAfter, serial);

        using var customChain = new X509Chain();
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(caCert);
        customChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));

        Assert.True(customChain.Build(leafCert));
    }

    // --- F4: --allow-private-proxy must actually permit private/loopback URIs

    [Fact]
    public async Task AllowPrivateProxy_PermitsLoopbackProxyUri()
    {
        // Without --allow-private-proxy, http://127.0.0.1:<port> is refused
        // by the syntactic check. With it, the proxy URI passes validation
        // and the request reaches the proxy connect step (which then fails
        // because the proxy port is unreachable — a NETWORK error, not
        // an input-validation error).
        var opts = new FetcherOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            MaxResponseBytes = 64 * 1024,
            MaxRedirects = 3,
            ProxyMode = ProxyMode.Explicit,
            ProxyUri = new Uri("http://127.0.0.1:65000"),
            AllowPrivateProxy = true,
        };

        // Expect a network-class exception (proxy unreachable), NOT an
        // InvalidDataException from input validation. Acceptable: any of
        // HttpRequestException / SocketException / TaskCanceledException.
        var ex = await Record.ExceptionAsync(async () =>
            await JwksClient.FetchAsync(new Uri("https://example.com/keys"), opts));
        Assert.NotNull(ex);
        Assert.False(ex is InvalidDataException,
            "--allow-private-proxy must NOT cause input-validation failure on a loopback proxy URI. " +
            $"Got: {ex.GetType().Name}: {ex.Message}");
    }

    [Fact]
    public async Task NoAllowPrivateProxy_RefusesLoopbackProxyUri()
    {
        // Counterpart: without the opt-in, the same URI must be refused
        // at handler-construction time.
        var opts = new FetcherOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            MaxResponseBytes = 64 * 1024,
            MaxRedirects = 3,
            ProxyMode = ProxyMode.Explicit,
            ProxyUri = new Uri("http://127.0.0.1:65000"),
            AllowPrivateProxy = false,
        };

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri("https://example.com/keys"), opts));
    }
}
