using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JwtDecoder.JwksFetcher.Tests;

/// <summary>
/// A minimal Kestrel HTTPS server bound to loopback with a self-signed cert,
/// used as the test substrate for <see cref="JwksClient"/> /
/// <see cref="OidcDiscoveryClient"/> integration tests.
/// </summary>
/// <remarks>
/// Tests pass the server's cert as <c>FetcherOptions.CaBundlePath</c> and set
/// the internal-only <c>AllowLoopbackForTesting</c> flag so the SSRF policy
/// permits 127.0.0.1.
/// </remarks>
internal sealed class HttpsTestServer : IAsyncDisposable
{
    public Uri BaseAddress { get; }
    public string CaBundlePath { get; }

    private readonly IHost _host;
    private readonly string _caTempDir;

    private HttpsTestServer(IHost host, Uri baseAddress, string caBundlePath, string caTempDir)
    {
        _host = host;
        BaseAddress = baseAddress;
        CaBundlePath = caBundlePath;
        _caTempDir = caTempDir;
    }

    public static async Task<HttpsTestServer> StartAsync(Action<WebApplication> configure)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        var now = DateTimeOffset.UtcNow;
        using var selfSigned = req.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));

        // Re-import via PFX so the cert+key are usable for TLS on all OSes.
        var pfxBytes = selfSigned.Export(X509ContentType.Pfx);
        var serverCert = X509CertificateLoader.LoadPkcs12(pfxBytes, password: null, X509KeyStorageFlags.Exportable);

        // Persist the cert as a PEM file for FetcherOptions.CaBundlePath.
        string tempDir = Path.Combine(Path.GetTempPath(), "JwksFetcherTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string caBundlePath = Path.Combine(tempDir, "ca.pem");
        File.WriteAllText(caBundlePath,
            "-----BEGIN CERTIFICATE-----\n" +
            Convert.ToBase64String(serverCert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
            "\n-----END CERTIFICATE-----\n");

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(opts =>
        {
            opts.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(serverCert));
        });
        builder.WebHost.UseUrls("https://127.0.0.1:0");

        var app = builder.Build();
        configure(app);
        await app.StartAsync();

        // Discover the actual bound URL.
        var addressFeature = app.Services
            .GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features
            .Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()
            ?? throw new InvalidOperationException("Could not obtain server addresses.");
        string url = addressFeature.Addresses.First(u => u.StartsWith("https://", StringComparison.Ordinal));

        return new HttpsTestServer(app, new Uri(url + "/"), caBundlePath, tempDir);
    }

    public async ValueTask DisposeAsync()
    {
        try { await _host.StopAsync(TimeSpan.FromSeconds(5)); } catch { }
        _host.Dispose();
        try { Directory.Delete(_caTempDir, recursive: true); } catch { }
    }
}
