using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class OidcDiscoveryClientTests
{
    private static string MetadataJson(string issuer, string jwksUri) =>
        $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{jwksUri}\",\"response_types_supported\":[\"code\"]}}";

    private static FetcherOptions Opts(HttpsTestServer server, byte[]? bearer = null, bool sendBearerToDiscovery = false) => new()
    {
        Timeout = TimeSpan.FromSeconds(5),
        MaxResponseBytes = 64 * 1024,
        MaxRedirects = 3,
        CaBundlePath = server.CaBundlePath,
        BearerTokenBytes = bearer,
        AllowLoopbackForTesting = true,
        SendBearerToDiscovery = sendBearerToDiscovery,
    };

    [Fact]
    public async Task DiscoverAndFetchJwks_FullFlow_Works()
    {
        HttpsTestServer? srv = null;
        srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                string issuer = $"https://{ctx.Request.Host}";
                string jwks = $"https://{ctx.Request.Host}/keys";
                return Results.Text(MetadataJson(issuer, jwks), "application/json").ExecuteAsync(ctx);
            });
            app.MapGet("/keys", () => Results.Text("{\"keys\":[]}", "application/json"));
        });

        try
        {
            // Trim trailing slash so issuer normalization works (BaseAddress always has /).
            var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));
            var result = await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(issuer, Opts(srv));

            Assert.Equal("{\"keys\":[]}", Encoding.UTF8.GetString(result.JwksDocument));
            Assert.EndsWith("/keys", result.JwksUri.AbsolutePath);
            Assert.False(result.CrossHostJwksUri);
        }
        finally { await srv.DisposeAsync(); }
    }

    [Fact]
    public async Task DiscoverAndFetchJwks_IssuerMismatch_Refused()
    {
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                // Server LIES about its issuer.
                return Results.Text(MetadataJson("https://attacker.example", "https://attacker.example/keys"),
                                    "application/json").ExecuteAsync(ctx);
            });
        });

        var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(issuer, Opts(srv)));
        Assert.Contains("issuer mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DiscoverAndFetchJwks_DoesNotSendBearerOnDiscoveryByDefault()
    {
        string? discoveryAuth = null;
        string? jwksAuth = null;
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                discoveryAuth = ctx.Request.Headers.Authorization;
                string issuer = $"https://{ctx.Request.Host}";
                return Results.Text(MetadataJson(issuer, $"{issuer}/keys"),
                                    "application/json").ExecuteAsync(ctx);
            });
            app.MapGet("/keys", ctx =>
            {
                jwksAuth = ctx.Request.Headers.Authorization;
                return Results.Text("{\"keys\":[]}", "application/json").ExecuteAsync(ctx);
            });
        });

        var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));
        await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(
            issuer,
            Opts(srv, bearer: Encoding.UTF8.GetBytes("tok"), sendBearerToDiscovery: false));

        Assert.True(string.IsNullOrEmpty(discoveryAuth),
            "Default policy: bearer must NOT be sent to the discovery hop. Was: " + discoveryAuth);
        Assert.Equal("Bearer tok", jwksAuth);
    }

    [Fact]
    public async Task DiscoverAndFetchJwks_SendsBearerOnDiscoveryWhenOptedIn()
    {
        string? discoveryAuth = null;
        await using var srv = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/.well-known/openid-configuration", ctx =>
            {
                discoveryAuth = ctx.Request.Headers.Authorization;
                string issuer = $"https://{ctx.Request.Host}";
                return Results.Text(MetadataJson(issuer, $"{issuer}/keys"),
                                    "application/json").ExecuteAsync(ctx);
            });
            app.MapGet("/keys", () => Results.Text("{\"keys\":[]}", "application/json"));
        });

        var issuer = new Uri(srv.BaseAddress.ToString().TrimEnd('/'));
        await OidcDiscoveryClient.DiscoverAndFetchJwksAsync(
            issuer,
            Opts(srv, bearer: Encoding.UTF8.GetBytes("tok"), sendBearerToDiscovery: true));

        Assert.Equal("Bearer tok", discoveryAuth);
    }

    [Fact]
    public async Task DiscoverAndFetchJwks_RefusesWellKnownInIssuerInput()
    {
        await using var srv = await HttpsTestServer.StartAsync(_ => { });
        Assert.Throws<InvalidDataException>(() =>
            OidcDiscoveryDocument.BuildDiscoveryUrl(
                new Uri(srv.BaseAddress, ".well-known/openid-configuration")));
    }
}
