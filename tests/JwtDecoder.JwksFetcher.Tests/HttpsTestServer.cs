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

    public static async Task<HttpsTestServer> StartAsync(
        Action<WebApplication> configure,
        string? sanHost = null,
        bool useCodeSigningEkuOnly = false)
    {
        using var rsa = RSA.Create(2048);

        // Use a unique CN per HttpsTestServer instance. The cross-host
        // jwks_uri test runs two simultaneous servers and concatenates
        // BOTH self-signed roots into one custom trust store. Linux
        // OpenSSL's chain builder distinguishes candidate roots by
        // subject DN; two roots with identical CN=localhost confuse the
        // signature-verification path and a TLS handshake to either
        // server can fail with "The SSL connection could not be
        // established". Windows CryptoAPI and macOS SecurityFramework
        // are lenient here, which is why this only surfaced on Linux.
        // SAN remains the authoritative hostname matcher (RFC 6125 has
        // deprecated CN-based hostname matching for over a decade).
        string subjectCn = sanHost ?? ("jwks-test-" + Guid.NewGuid().ToString("N").Substring(0, 12));
        var req = new CertificateRequest("CN=" + subjectCn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // SubjectKeyIdentifier helps OpenSSL match a cert to its trust-
        // store entry even when subjects collide, by giving each cert
        // a unique fingerprint derived from its public key. Adding this
        // is also proper PKI hygiene — real-world CA certs always
        // declare SKI.
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));

        var san = new SubjectAlternativeNameBuilder();
        if (sanHost is null)
        {
            // Default: bind to loopback and trust loopback. Standard happy-path
            // fixture used by every existing test.
            san.AddDnsName("localhost");
            san.AddIpAddress(IPAddress.Loopback);
        }
        else
        {
            // Custom: serve a cert whose SAN does NOT match the actual host
            // we listen on (127.0.0.1). This is the fixture used by the
            // "--ca-bundle must still reject hostname mismatch" test
            // (final-review B1). Intentionally omits the IP SAN.
            san.AddDnsName(sanHost);
        }
        req.CertificateExtensions.Add(san.Build());

        if (useCodeSigningEkuOnly)
        {
            // EKU = Code Signing ONLY (no Server Authentication). Fixture for the
            // F1 regression test: a cert signed by the trusted custom CA but
            // not intended for HTTPS server use should be refused by the
            // --ca-bundle path even if the SAN matches.
            var ekus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") };
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, critical: false));
        }
        else
        {
            // EKU = Server Authentication. Real-world server certs ALWAYS
            // declare EKU explicitly (RFC 5280 §4.2.1.12; CAB/Forum baseline
            // requirements §7.1.2.7.6). Without this, Linux/OpenSSL's
            // X509Chain refuses the cert when the production code's
            // ChainPolicy.ApplicationPolicy specifies ServerAuth (the F1
            // fix in JwksClient.cs) — even though Windows/CryptoAPI treats
            // an absent EKU as "any purpose". Tests previously passed only
            // on Windows runners; CI Linux runners failed with "The SSL
            // connection could not be established" because the chain build
            // returned false for the policy-mismatch.
            var ekus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, critical: false));
        }
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
