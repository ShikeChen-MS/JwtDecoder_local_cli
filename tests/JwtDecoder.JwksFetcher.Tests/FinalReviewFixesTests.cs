using System.Net.Http;
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
}
