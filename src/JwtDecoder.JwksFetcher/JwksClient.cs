using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace JwtDecoder.JwksFetcher;

/// <summary>The outcome of a successful HTTPS fetch.</summary>
/// <param name="FinalUri">The URL the request landed on (may differ from the
/// originally-requested URL if redirects were followed).</param>
/// <param name="Body">The response body bytes, capped at <see cref="FetcherOptions.MaxResponseBytes"/>.</param>
public sealed record FetchResult(Uri FinalUri, byte[] Body);

/// <summary>
/// HTTPS GET client used by both the direct JWKS fetch and the OIDC discovery
/// flow. Applies the layered network hardening defined in the JWKS companion
/// design plan (round-2 review addendum).
/// </summary>
/// <remarks>
/// Per request, the handler is configured as follows:
/// <list type="bullet">
/// <item><c>AllowAutoRedirect = false</c>; redirects are driven by a manual
/// loop here so SSRF rules and the redirect-cap / loop-detection apply per hop.</item>
/// <item><c>UseProxy</c> is set per <see cref="FetcherOptions.ProxyMode"/>;
/// default is no proxy. When a proxy is in use, the proxy joins the trust chain.</item>
/// <item><c>AutomaticDecompression = None</c> so the body cap can't be bypassed
/// by a compression bomb. Any <c>Content-Encoding</c> response header is refused.</item>
/// <item>TLS protocols pinned to TLS 1.2 / 1.3. ALPN advertises HTTP/2 and
/// HTTP/1.1 only — HTTP/3 is intentionally not negotiated.</item>
/// <item><c>ConnectCallback</c> performs our own DNS resolution, validates
/// every resolved address with <see cref="SsrfPolicy.IsForbiddenAddress"/>, and
/// connects by <see cref="IPEndPoint"/> — defeating DNS rebinding. Skipped
/// transparently when a proxy is configured (the proxy resolves the destination).</item>
/// <item>Bearer token is attached only to the originally-requested URL; on any
/// redirect (including same-host) the <c>Authorization</c> header is stripped.</item>
/// <item><c>CaBundlePath</c>, when given, REPLACES the system trust store for
/// this fetch — only CAs in the bundle are accepted.</item>
/// </list>
/// </remarks>
public static class JwksClient
{
    /// <summary>Hard caps that override <see cref="FetcherOptions"/> values when they are too generous.</summary>
    public const int HardMaxResponseBytes = 1 * 1024 * 1024;
    public const int HardMaxRedirects = 5;
    public static readonly TimeSpan HardMaxTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Fetch a single HTTPS resource, following safe redirects.</summary>
    /// <exception cref="ArgumentNullException">If <paramref name="uri"/> or <paramref name="options"/> is null.</exception>
    /// <exception cref="InvalidDataException">If a security rule refused the request or response.</exception>
    /// <exception cref="HttpRequestException">If the HTTP request failed (network or non-success status).</exception>
    public static async Task<FetchResult> FetchAsync(Uri uri, FetcherOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(options);

        SsrfPolicy.AssertHostnameAllowed(uri, options.AllowLoopbackForTesting);
        ValidateOptions(options);

        using HttpClientHandler? _ = null; // for the lifetime grep below
        var handler = BuildHandler(options);
        using var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Min(options.Timeout, HardMaxTimeout),
        };

        return await FetchWithRedirectsAsync(client, uri, options, ct);
    }

    private static async Task<FetchResult> FetchWithRedirectsAsync(
        HttpClient client, Uri originalUri, FetcherOptions options, CancellationToken ct)
    {
        int maxRedirects = Math.Min(options.MaxRedirects, HardMaxRedirects);
        int maxBytes = Math.Min(options.MaxResponseBytes, HardMaxResponseBytes);

        Uri current = originalUri;
        var seen = new HashSet<Uri> { current };
        int redirects = 0;

        while (true)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, current)
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            };

            // Bearer token attaches ONLY on the original URL. Round-2 review:
            // strip on every redirect, even same-host, to prevent token leakage.
            if (options.BearerTokenBytes is { Length: > 0 } && current.Equals(originalUri))
            {
                // The bearer bytes inevitably become a string at the header
                // boundary; the caller's byte[] is what callers can zero.
                string tokenStr = Encoding.UTF8.GetString(options.BearerTokenBytes);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenStr);
            }

            if (options.ExtraHeaders is not null && current.Equals(originalUri))
            {
                // Mirror bearer-token handling: extra headers (--header-file) are
                // attached ONLY to the originally-requested URL. A redirect target
                // — even same-host — does not receive them. Otherwise an
                // X-Api-Key / X-Auth-Token in --header-file would leak the same
                // way a Bearer would. (Final-review I4.)
                foreach (var (name, value) in options.ExtraHeaders)
                {
                    if (IsDangerousHeader(name))
                        throw new InvalidDataException(
                            $"Refusing extra request header '{name}': hop-by-hop / auth / routing headers are not permitted.");
                    req.Headers.Add(name, value);
                }
            }

            using var resp = await client.SendAsync(
                req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            // --- Redirect handling. ---
            int status = (int)resp.StatusCode;
            if (status >= 300 && status < 400 && resp.Headers.Location is not null)
            {
                Uri location = resp.Headers.Location;
                Uri next = location.IsAbsoluteUri ? location : new Uri(current, location);

                if (++redirects > maxRedirects)
                    throw new InvalidDataException(
                        $"Refusing to follow more than {maxRedirects} redirects (last: '{next}').");

                if (!string.Equals(next.Scheme, "https", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        $"Refusing non-HTTPS redirect to '{next}'.");

                if (!seen.Add(next))
                    throw new InvalidDataException(
                        $"Redirect loop detected: '{next}' was already visited.");

                SsrfPolicy.AssertHostnameAllowed(next, options.AllowLoopbackForTesting);
                current = next;
                continue;
            }

            // --- Non-redirect: read and bound the body. ---
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException(
                    $"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} from '{current}'.",
                    inner: null, statusCode: resp.StatusCode);

            // Refuse explicit Content-Encoding (we disabled automatic decompression).
            if (resp.Content.Headers.ContentEncoding.Count > 0)
                throw new InvalidDataException(
                    $"Refusing response with Content-Encoding '{string.Join(",", resp.Content.Headers.ContentEncoding)}'; " +
                    "the client does not negotiate compression.");

            byte[] body = await ReadBoundedAsync(resp, maxBytes, ct).ConfigureAwait(false);
            return new FetchResult(current, body);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        // If the server advertised Content-Length, refuse early on overflow.
        long? len = resp.Content.Headers.ContentLength;
        if (len.HasValue && len.Value > maxBytes)
            throw new InvalidDataException(
                $"Response Content-Length {len.Value:N0} exceeds maximum of {maxBytes:N0} bytes.");

        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var ms = new MemoryStream();
        byte[] buf = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        int total = 0;
        while (true)
        {
            int n = await stream.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false);
            if (n <= 0) break;
            if (total + n > maxBytes)
                throw new InvalidDataException(
                    $"Response body exceeds maximum of {maxBytes:N0} bytes.");
            ms.Write(buf, 0, n);
            total += n;
        }
        return ms.ToArray();
    }

    private static SocketsHttpHandler BuildHandler(FetcherOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ConnectTimeout = Min(options.Timeout, HardMaxTimeout),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11,
                },
            },
        };

        // --- Proxy configuration. ---
        switch (options.ProxyMode)
        {
            case ProxyMode.None:
                handler.UseProxy = false;
                break;
            case ProxyMode.Explicit:
                if (options.ProxyUri is null)
                    throw new InvalidDataException("ProxyMode=Explicit requires ProxyUri.");
                // Syntactic check (refuses non-HTTPS proxies, IP literals in
                // private/loopback ranges, literal localhost) always runs.
                SsrfPolicy.AssertHostnameAllowed(options.ProxyUri, allowLoopbackForTesting: false);
                if (!options.AllowPrivateProxy)
                {
                    // DNS-resolve the proxy hostname and refuse if any
                    // resolved address is in a deny-list range. The syntactic
                    // check alone misses cases where a public-looking
                    // hostname resolves to 127.0.0.1 / 10.x / 169.254 / ...
                    // (Final-review I5.)
                    IPAddress[] addrs;
                    try { addrs = Dns.GetHostAddresses(options.ProxyUri.Host); }
                    catch (System.Net.Sockets.SocketException ex)
                    {
                        throw new InvalidDataException(
                            $"Proxy hostname '{options.ProxyUri.Host}' could not be resolved: {ex.Message}", ex);
                    }
                    foreach (var a in addrs)
                    {
                        if (SsrfPolicy.IsForbiddenAddress(a, allowLoopbackForTesting: false))
                            throw new InvalidDataException(
                                $"Proxy '{options.ProxyUri}' resolves to forbidden address {a}; " +
                                "pass --allow-private-proxy to permit local-debug proxies (mitmproxy/Fiddler).");
                    }
                }
                handler.UseProxy = true;
                handler.Proxy = new WebProxy(options.ProxyUri)
                {
                    UseDefaultCredentials = options.ProxyDefaultCredentials,
                };
                break;
            case ProxyMode.System:
                handler.UseProxy = true;
                if (options.ProxyDefaultCredentials)
                    handler.DefaultProxyCredentials = CredentialCache.DefaultCredentials;
                break;
        }

        // --- ConnectCallback: DNS rebinding defence. Skipped when proxy is in use. ---
        if (options.ProxyMode == ProxyMode.None)
        {
            bool allowLoopback = options.AllowLoopbackForTesting;
            handler.ConnectCallback = async (ctx, ctk) =>
            {
                IPAddress[] addrs;
                try
                {
                    addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ctk).ConfigureAwait(false);
                }
                catch (SocketException ex)
                {
                    throw new HttpRequestException(
                        $"DNS resolution failed for '{ctx.DnsEndPoint.Host}': {ex.Message}", ex);
                }

                if (addrs.Length == 0)
                    throw new HttpRequestException(
                        $"DNS returned no addresses for '{ctx.DnsEndPoint.Host}'.");

                foreach (var a in addrs)
                {
                    if (SsrfPolicy.IsForbiddenAddress(a, allowLoopback))
                        throw new InvalidDataException(
                            $"DNS for '{ctx.DnsEndPoint.Host}' resolved to forbidden address {a}; refusing to connect (SSRF guard).");
                }

                Exception? lastEx = null;
                foreach (var a in addrs)
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(a, ctx.DnsEndPoint.Port), ctk).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception ex)
                    {
                        socket.Dispose();
                        lastEx = ex;
                    }
                }
                throw new HttpRequestException(
                    $"Could not connect to '{ctx.DnsEndPoint.Host}:{ctx.DnsEndPoint.Port}'.", lastEx);
            };
        }

        // --- CA bundle: REPLACE system trust store when set. ---
        if (options.CaBundlePath is not null)
        {
            var trustedRoots = LoadPemCertificateCollection(options.CaBundlePath);
            handler.SslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                if (cert is null) return false;

                // --ca-bundle REPLACES the system trust store, so we are willing
                // to override RemoteCertificateChainErrors. We MUST NOT override
                // RemoteCertificateNameMismatch (the cert's SAN didn't match the
                // hostname we connected to) or RemoteCertificateNotAvailable
                // (peer offered no cert) — those are authenticity guarantees,
                // not trust-anchor questions. A cert signed by the supplied CA
                // for attacker.example would otherwise authenticate any host.
                if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
                if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;

                using var customChain = new X509Chain();
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.CustomTrustStore.AddRange(trustedRoots);
                // Also build any intermediates supplied in the chain into ExtraStore.
                if (chain is not null)
                {
                    foreach (var ce in chain.ChainElements)
                        customChain.ChainPolicy.ExtraStore.Add(ce.Certificate);
                }
                return customChain.Build((X509Certificate2)cert);
            };
        }

        return handler;
    }

    private static X509Certificate2Collection LoadPemCertificateCollection(string path)
    {
        string pem;
        try { pem = File.ReadAllText(path); }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Could not read CA bundle '{path}': {ex.Message}", ex);
        }
        var coll = new X509Certificate2Collection();
        try { coll.ImportFromPem(pem); }
        catch (Exception ex)
        {
            throw new InvalidDataException($"CA bundle '{path}' is not valid PEM: {ex.Message}", ex);
        }
        if (coll.Count == 0)
            throw new InvalidDataException($"CA bundle '{path}' contains no certificates.");
        return coll;
    }

    private static void ValidateOptions(FetcherOptions options)
    {
        if (options.Timeout <= TimeSpan.Zero)
            throw new InvalidDataException("FetcherOptions.Timeout must be positive.");
        if (options.MaxResponseBytes <= 0)
            throw new InvalidDataException("FetcherOptions.MaxResponseBytes must be positive.");
        if (options.MaxRedirects < 0)
            throw new InvalidDataException("FetcherOptions.MaxRedirects must be ≥ 0.");
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    /// <summary>Hop-by-hop / auth / routing headers that must never be supplied via <c>--header-file</c>.</summary>
    private static bool IsDangerousHeader(string name) => name switch
    {
        var n when string.Equals(n, "Host", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Authorization", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Proxy-Authorization", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Cookie", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Connection", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "TE", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Trailer", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Upgrade", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Expect", StringComparison.OrdinalIgnoreCase) => true,
        var n when string.Equals(n, "Content-Length", StringComparison.OrdinalIgnoreCase) => true,
        _ => false,
    };
}
