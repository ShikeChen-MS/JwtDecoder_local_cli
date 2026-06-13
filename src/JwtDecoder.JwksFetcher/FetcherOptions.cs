namespace JwtDecoder.JwksFetcher;

/// <summary>Proxy selection policy for the JWKS network layer.</summary>
public enum ProxyMode
{
    /// <summary>No proxy. <c>HTTP_PROXY</c>/<c>HTTPS_PROXY</c> env vars are ignored. Default.</summary>
    None = 0,
    /// <summary>Use the explicit URL in <see cref="FetcherOptions.ProxyUri"/>.</summary>
    Explicit,
    /// <summary>Honor .NET's default system / env-var proxy resolution.</summary>
    System,
}

/// <summary>
/// Configuration for one or more JWKS / OIDC discovery network fetches.
/// </summary>
/// <remarks>
/// Defaults are deliberately conservative: 10-second timeout, 256 KiB body cap,
/// 3 redirects, no proxy, no bearer token, system trust store.
/// </remarks>
public sealed class FetcherOptions
{
    /// <summary>Per-hop request timeout. Default 10 s, hard maximum 60 s.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Per-hop response body cap in bytes. Default 256 KiB, hard maximum 1 MiB.</summary>
    public int MaxResponseBytes { get; init; } = 256 * 1024;

    /// <summary>Maximum HTTPS-only redirects per hop. Default 3, hard maximum 5.</summary>
    public int MaxRedirects { get; init; } = 3;

    /// <summary>
    /// Optional PEM CA bundle that REPLACES the system trust store for TLS
    /// validation. When set, the system trust store is bypassed; only the
    /// CAs in this bundle are trusted. Use for restricted environments.
    /// </summary>
    public string? CaBundlePath { get; init; }

    /// <summary>
    /// Optional bearer token bytes for <c>Authorization: Bearer ...</c>.
    /// Stored as <see cref="byte"/>[] to avoid leaking secret string instances.
    /// The bytes are read by <c>JwksClient</c> once per fetch and never echoed
    /// to stdout/stderr.
    /// </summary>
    public byte[]? BearerTokenBytes { get; init; }

    /// <summary>
    /// Extra HTTP request headers, already validated by the CLI layer
    /// against the dangerous-header denylist (Host, Authorization, etc.).
    /// </summary>
    public IReadOnlyList<(string Name, string Value)>? ExtraHeaders { get; init; }

    /// <summary>Proxy selection policy. Default <see cref="ProxyMode.None"/>.</summary>
    public ProxyMode ProxyMode { get; init; } = ProxyMode.None;

    /// <summary>Required when <see cref="ProxyMode"/> is <see cref="ProxyMode.Explicit"/>.</summary>
    public Uri? ProxyUri { get; init; }

    /// <summary>Send OS default credentials (NTLM/Kerberos transparent SSO) to the proxy.</summary>
    public bool ProxyDefaultCredentials { get; init; }

    /// <summary>
    /// Allow proxy URLs whose hostname resolves to a private/loopback address
    /// (for local-debug proxies like mitmproxy/Fiddler). Off by default.
    /// </summary>
    public bool AllowPrivateProxy { get; init; }

    /// <summary>
    /// Internal-only test escape hatch. When true, <c>SsrfPolicy</c> permits
    /// loopback addresses (127.0.0.0/8 and ::1) — so test fixtures can run a
    /// Kestrel HTTPS server on localhost. The CLI never sets this.
    /// </summary>
    internal bool AllowLoopbackForTesting { get; init; }

    /// <summary>
    /// When true (and <see cref="BearerTokenBytes"/> is set), <c>OidcDiscoveryClient</c>
    /// attaches the bearer token to the discovery hop too (opt-in per the
    /// round-2 review).
    /// </summary>
    public bool SendBearerToDiscovery { get; init; }
}
