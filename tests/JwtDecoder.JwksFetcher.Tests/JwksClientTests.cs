using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class JwksClientTests
{
    private static FetcherOptions OptsFor(HttpsTestServer server, FetcherOptions? overrides = null)
    {
        return new FetcherOptions
        {
            Timeout = overrides?.Timeout ?? TimeSpan.FromSeconds(5),
            MaxResponseBytes = overrides?.MaxResponseBytes ?? 64 * 1024,
            MaxRedirects = overrides?.MaxRedirects ?? 3,
            CaBundlePath = server.CaBundlePath,
            BearerTokenBytes = overrides?.BearerTokenBytes,
            ExtraHeaders = overrides?.ExtraHeaders,
            ProxyMode = overrides?.ProxyMode ?? ProxyMode.None,
            ProxyUri = overrides?.ProxyUri,
            ProxyDefaultCredentials = overrides?.ProxyDefaultCredentials ?? false,
            AllowPrivateProxy = overrides?.AllowPrivateProxy ?? false,
            AllowLoopbackForTesting = true,
            SendBearerToDiscovery = overrides?.SendBearerToDiscovery ?? false,
        };
    }

    [Fact]
    public async Task FetchAsync_HappyPath_ReturnsBody()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/keys", () => Results.Text("{\"keys\":[]}", "application/json"));
        });

        var result = await JwksClient.FetchAsync(new Uri(server.BaseAddress, "keys"), OptsFor(server));

        Assert.Equal("{\"keys\":[]}", Encoding.UTF8.GetString(result.Body));
        Assert.Equal(server.BaseAddress.Authority, result.FinalUri.Authority);
    }

    [Fact]
    public async Task FetchAsync_OversizedBody_Rejected()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            // Server emits 100 KB but the client cap is 1 KB.
            app.MapGet("/big", () => Results.Bytes(new byte[100 * 1024], "application/octet-stream"));
        });

        var opts = OptsFor(server, new FetcherOptions { MaxResponseBytes = 1024 });
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "big"), opts));
    }

    [Fact]
    public async Task FetchAsync_ContentLengthDeclaredTooBig_RejectedEarly()
    {
        // Emit body with declared Content-Length above the cap. We don't read it.
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/big", async ctx =>
            {
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.ContentLength = 100_000;
                ctx.Response.ContentType = "application/octet-stream";
                await ctx.Response.Body.WriteAsync(new byte[1]);
            });
        });

        var opts = OptsFor(server, new FetcherOptions { MaxResponseBytes = 1024 });
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "big"), opts));
    }

    [Fact]
    public async Task FetchAsync_FollowsRedirectWithinCap()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/r1", ctx => { ctx.Response.Redirect("/r2", permanent: false); return Task.CompletedTask; });
            app.MapGet("/r2", () => Results.Text("ok", "text/plain"));
        });

        var result = await JwksClient.FetchAsync(new Uri(server.BaseAddress, "r1"), OptsFor(server));

        Assert.Equal("ok", Encoding.UTF8.GetString(result.Body));
        Assert.EndsWith("/r2", result.FinalUri.AbsolutePath);
    }

    [Fact]
    public async Task FetchAsync_RedirectCapExceeded_Rejected()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/a", ctx => { ctx.Response.Redirect("/b"); return Task.CompletedTask; });
            app.MapGet("/b", ctx => { ctx.Response.Redirect("/c"); return Task.CompletedTask; });
            app.MapGet("/c", ctx => { ctx.Response.Redirect("/d"); return Task.CompletedTask; });
            app.MapGet("/d", () => Results.Text("never", "text/plain"));
        });

        var opts = OptsFor(server, new FetcherOptions { MaxRedirects = 2 });
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "a"), opts));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchAsync_NonHttpsRedirect_Rejected()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/r", ctx =>
            {
                ctx.Response.Headers.Location = "http://example.com/";
                ctx.Response.StatusCode = 302;
                return Task.CompletedTask;
            });
        });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "r"), OptsFor(server)));
        Assert.Contains("non-HTTPS", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchAsync_RedirectLoop_Rejected()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/loop", ctx => { ctx.Response.Redirect("/loop"); return Task.CompletedTask; });
        });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "loop"), OptsFor(server)));
        Assert.Contains("loop", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchAsync_Bearer_AttachedOnOriginalUrl()
    {
        string? capturedAuth = null;
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/k", ctx =>
            {
                capturedAuth = ctx.Request.Headers.Authorization;
                return Results.Text("ok", "text/plain").ExecuteAsync(ctx);
            });
        });

        var opts = OptsFor(server, new FetcherOptions
        {
            BearerTokenBytes = Encoding.UTF8.GetBytes("s3cr3t"),
        });
        await JwksClient.FetchAsync(new Uri(server.BaseAddress, "k"), opts);

        Assert.Equal("Bearer s3cr3t", capturedAuth);
    }

    [Fact]
    public async Task FetchAsync_Bearer_StrippedOnRedirect()
    {
        string? capturedAuthFirstHop = null;
        string? capturedAuthSecondHop = null;
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/first", ctx =>
            {
                capturedAuthFirstHop = ctx.Request.Headers.Authorization;
                ctx.Response.Redirect("/second");
                return Task.CompletedTask;
            });
            app.MapGet("/second", ctx =>
            {
                capturedAuthSecondHop = ctx.Request.Headers.Authorization;
                return Results.Text("ok", "text/plain").ExecuteAsync(ctx);
            });
        });

        var opts = OptsFor(server, new FetcherOptions
        {
            BearerTokenBytes = Encoding.UTF8.GetBytes("topsecret"),
        });
        await JwksClient.FetchAsync(new Uri(server.BaseAddress, "first"), opts);

        Assert.Equal("Bearer topsecret", capturedAuthFirstHop);
        Assert.True(string.IsNullOrEmpty(capturedAuthSecondHop),
            "Authorization header MUST be stripped on redirect (round-2 review). Was: " + capturedAuthSecondHop);
    }

    [Theory]
    [InlineData("Host")]
    [InlineData("Authorization")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Cookie")]
    [InlineData("Transfer-Encoding")]
    public async Task FetchAsync_DangerousExtraHeader_Refused(string headerName)
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/k", () => Results.Text("ok", "text/plain")));

        var opts = OptsFor(server, new FetcherOptions
        {
            ExtraHeaders = new[] { (headerName, "value") },
        });
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "k"), opts));
        Assert.Contains(headerName, ex.Message);
    }

    [Fact]
    public async Task FetchAsync_BenignExtraHeader_PassedThrough()
    {
        string? captured = null;
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/k", ctx =>
            {
                captured = ctx.Request.Headers["X-Custom"];
                return Results.Text("ok", "text/plain").ExecuteAsync(ctx);
            });
        });

        var opts = OptsFor(server, new FetcherOptions
        {
            ExtraHeaders = new[] { ("X-Custom", "value") },
        });
        await JwksClient.FetchAsync(new Uri(server.BaseAddress, "k"), opts);
        Assert.Equal("value", captured);
    }

    [Fact]
    public async Task FetchAsync_NonSuccessStatus_Throws()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/k", () => Results.NotFound());
        });

        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "k"), OptsFor(server)));
    }

    [Fact]
    public async Task FetchAsync_ContentEncodingResponse_Refused()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
        {
            app.MapGet("/gz", async ctx =>
            {
                ctx.Response.Headers.ContentEncoding = "gzip";
                ctx.Response.ContentType = "application/octet-stream";
                await ctx.Response.Body.WriteAsync(new byte[] { 0x1f, 0x8b });
            });
        });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "gz"), OptsFor(server)));
        Assert.Contains("Content-Encoding", ex.Message);
    }

    [Fact]
    public async Task FetchAsync_NoCaBundle_RejectsSelfSignedServerCert()
    {
        await using var server = await HttpsTestServer.StartAsync(app =>
            app.MapGet("/k", () => Results.Text("ok", "text/plain")));

        // Build options WITHOUT a CA bundle. System trust store should reject
        // the test server's self-signed cert.
        var opts = new FetcherOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            MaxResponseBytes = 64 * 1024,
            MaxRedirects = 3,
            AllowLoopbackForTesting = true,
            // CaBundlePath: null   <- the test
        };

        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await JwksClient.FetchAsync(new Uri(server.BaseAddress, "k"), opts));
    }

    [Fact]
    public async Task FetchAsync_RefusesNonHttpsUri()
    {
        var opts = new FetcherOptions { AllowLoopbackForTesting = true };
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri("http://example.com/k"), opts));
    }

    [Fact]
    public async Task FetchAsync_RefusesPrivateIpLiteral()
    {
        // AllowLoopback is true but 10.0.0.1 is in 10/8, still refused.
        var opts = new FetcherOptions { AllowLoopbackForTesting = true };
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await JwksClient.FetchAsync(new Uri("https://10.0.0.1/"), opts));
    }
}
