using System.Reflection;
using JwtDecoder.JwksFetcher;

namespace JwksFetch;

/// <summary>Parsed jwksfetch options.</summary>
internal sealed class JwksFetchOptions
{
    // Key sources (exactly one required).
    public Uri? JwksUrl { get; init; }
    public Uri? FromIssuer { get; init; }
    public string? JwksFile { get; init; }

    // Token source.
    public string? TokenFile { get; init; }

    // Network options.
    public string? BearerTokenFile { get; init; }
    public bool BearerTokenDiscovery { get; init; }
    public string? HeaderFile { get; init; }
    public string? CaBundle { get; init; }
    public int TimeoutSeconds { get; init; } = 10;
    public int MaxResponseBytes { get; init; } = 256 * 1024;
    public int MaxRedirects { get; init; } = 3;
    public bool RequireSameHostJwksUri { get; init; }

    // Proxy.
    public ProxyMode ProxyMode { get; init; } = ProxyMode.None;
    public Uri? ProxyUri { get; init; }
    public bool ProxyDefaultCredentials { get; init; }
    public bool AllowPrivateProxy { get; init; }

    // General.
    public bool Verbose { get; init; }
    public bool Help { get; init; }
    public bool Version { get; init; }
}

internal static class Cli
{
    public static string VersionString =>
        typeof(Cli).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(Cli).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    public static (JwksFetchOptions? options, string? error) Parse(string[] args)
    {
        Uri? jwksUrl = null;
        Uri? fromIssuer = null;
        string? jwksFile = null;
        string? tokenFile = null;
        string? bearerFile = null;
        bool bearerDiscovery = false;
        string? headerFile = null;
        string? caBundle = null;
        int timeoutSec = 10;
        int maxResp = 256 * 1024;
        int maxRedir = 3;
        bool requireSameHost = false;
        ProxyMode pmode = ProxyMode.None;
        Uri? proxyUri = null;
        bool proxyDefaultCreds = false;
        bool allowPrivateProxy = false;
        bool useSystemProxy = false;
        bool verbose = false;
        bool help = false;
        bool version = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-h":
                case "--help":
                    help = true; break;
                case "-V":
                case "--version":
                    version = true; break;
                case "-v":
                case "--verbose":
                    verbose = true; break;

                case "--jwks-url":
                    if (++i >= args.Length) return (null, "Error: --jwks-url requires an https URL.");
                    if (jwksUrl is not null) return (null, "Error: --jwks-url specified more than once.");
                    if (!Uri.TryCreate(args[i], UriKind.Absolute, out jwksUrl))
                        return (null, $"Error: --jwks-url '{args[i]}' is not a valid URL.");
                    break;

                case "--from-issuer":
                    if (++i >= args.Length) return (null, "Error: --from-issuer requires an https URL.");
                    if (fromIssuer is not null) return (null, "Error: --from-issuer specified more than once.");
                    if (!Uri.TryCreate(args[i], UriKind.Absolute, out fromIssuer))
                        return (null, $"Error: --from-issuer '{args[i]}' is not a valid URL.");
                    break;

                case "--jwks-file":
                    if (++i >= args.Length) return (null, "Error: --jwks-file requires a path.");
                    if (jwksFile is not null) return (null, "Error: --jwks-file specified more than once.");
                    jwksFile = args[i];
                    break;

                case "--token-file":
                    if (++i >= args.Length) return (null, "Error: --token-file requires a path.");
                    if (tokenFile is not null) return (null, "Error: --token-file specified more than once.");
                    tokenFile = args[i];
                    break;

                case "--bearer-token-file":
                    if (++i >= args.Length) return (null, "Error: --bearer-token-file requires a path.");
                    if (bearerFile is not null) return (null, "Error: --bearer-token-file specified more than once.");
                    bearerFile = args[i];
                    break;

                case "--bearer-token-discovery":
                    bearerDiscovery = true; break;

                case "--header-file":
                    if (++i >= args.Length) return (null, "Error: --header-file requires a path.");
                    if (headerFile is not null) return (null, "Error: --header-file specified more than once.");
                    headerFile = args[i];
                    break;

                case "--ca-bundle":
                    if (++i >= args.Length) return (null, "Error: --ca-bundle requires a path.");
                    if (caBundle is not null) return (null, "Error: --ca-bundle specified more than once.");
                    caBundle = args[i];
                    break;

                case "--timeout-seconds":
                    if (++i >= args.Length) return (null, "Error: --timeout-seconds requires an integer.");
                    if (!int.TryParse(args[i], out timeoutSec) || timeoutSec <= 0 || timeoutSec > 60)
                        return (null, "Error: --timeout-seconds must be 1..60.");
                    break;

                case "--max-response-bytes":
                    if (++i >= args.Length) return (null, "Error: --max-response-bytes requires an integer.");
                    if (!int.TryParse(args[i], out maxResp) || maxResp <= 0 || maxResp > JwksClient.HardMaxResponseBytes)
                        return (null, $"Error: --max-response-bytes must be 1..{JwksClient.HardMaxResponseBytes}.");
                    break;

                case "--max-redirects":
                    if (++i >= args.Length) return (null, "Error: --max-redirects requires an integer.");
                    if (!int.TryParse(args[i], out maxRedir) || maxRedir < 0 || maxRedir > JwksClient.HardMaxRedirects)
                        return (null, $"Error: --max-redirects must be 0..{JwksClient.HardMaxRedirects}.");
                    break;

                case "--require-same-host-jwks-uri":
                    requireSameHost = true; break;

                case "--proxy":
                    if (++i >= args.Length) return (null, "Error: --proxy requires a URL.");
                    if (proxyUri is not null) return (null, "Error: --proxy specified more than once.");
                    if (!Uri.TryCreate(args[i], UriKind.Absolute, out proxyUri))
                        return (null, $"Error: --proxy '{args[i]}' is not a valid URL.");
                    pmode = ProxyMode.Explicit;
                    break;

                case "--use-system-proxy":
                    useSystemProxy = true; break;

                case "--proxy-default-credentials":
                    proxyDefaultCreds = true; break;

                case "--allow-private-proxy":
                    allowPrivateProxy = true; break;

                default:
                    return (null, $"Error: unknown option '{a}'. Use --help for usage.");
            }
        }

        if (help || version)
            return (new JwksFetchOptions { Help = help, Version = version }, null);

        // --- Key-source mutual exclusion. ---
        int kSrc = (jwksUrl is not null ? 1 : 0) + (fromIssuer is not null ? 1 : 0) + (jwksFile is not null ? 1 : 0);
        if (kSrc == 0) return (null, "Error: one of --jwks-url, --from-issuer, --jwks-file is required.");
        if (kSrc > 1)  return (null, "Error: --jwks-url, --from-issuer, --jwks-file are mutually exclusive.");

        // --- Proxy options interplay. ---
        if (useSystemProxy && pmode == ProxyMode.Explicit)
            return (null, "Error: --use-system-proxy and --proxy are mutually exclusive.");
        if (useSystemProxy) pmode = ProxyMode.System;

        if (pmode == ProxyMode.None && proxyDefaultCreds)
            return (null, "Error: --proxy-default-credentials requires --proxy or --use-system-proxy.");
        if (pmode == ProxyMode.None && allowPrivateProxy)
            return (null, "Error: --allow-private-proxy requires --proxy or --use-system-proxy.");

        // --- Bearer / discovery interplay. ---
        if (bearerDiscovery && bearerFile is null)
            return (null, "Error: --bearer-token-discovery requires --bearer-token-file.");

        // --- jwks-file ignores network options that don't apply. ---
        if (jwksFile is not null)
        {
            if (bearerFile is not null) return (null, "Error: --bearer-token-file is meaningless with --jwks-file (no network).");
            if (headerFile is not null) return (null, "Error: --header-file is meaningless with --jwks-file (no network).");
            if (caBundle   is not null) return (null, "Error: --ca-bundle is meaningless with --jwks-file (no network).");
            if (pmode != ProxyMode.None) return (null, "Error: --proxy / --use-system-proxy is meaningless with --jwks-file (no network).");
        }

        // --- --require-same-host-jwks-uri is only meaningful with --from-issuer. ---
        if (requireSameHost && fromIssuer is null)
            return (null, "Error: --require-same-host-jwks-uri is only meaningful with --from-issuer.");

        return (new JwksFetchOptions
        {
            JwksUrl = jwksUrl,
            FromIssuer = fromIssuer,
            JwksFile = jwksFile,
            TokenFile = tokenFile,
            BearerTokenFile = bearerFile,
            BearerTokenDiscovery = bearerDiscovery,
            HeaderFile = headerFile,
            CaBundle = caBundle,
            TimeoutSeconds = timeoutSec,
            MaxResponseBytes = maxResp,
            MaxRedirects = maxRedir,
            RequireSameHostJwksUri = requireSameHost,
            ProxyMode = pmode,
            ProxyUri = proxyUri,
            ProxyDefaultCredentials = proxyDefaultCreds,
            AllowPrivateProxy = allowPrivateProxy,
            Verbose = verbose,
        }, null);
    }

    public static void PrintHelp(TextWriter w)
    {
        w.WriteLine("jwksfetch \u2014 acquire a single public verification key for a JWT from a JWKS endpoint.");
        w.WriteLine();
        w.WriteLine("USAGE:");
        w.WriteLine("  jwksfetch --jwks-url <https-url>     [--token-file <p> | (stdin)]");
        w.WriteLine("  jwksfetch --from-issuer <https-url>  [--token-file <p> | (stdin)]");
        w.WriteLine("  jwksfetch --jwks-file <path>         [--token-file <p> | (stdin)]");
        w.WriteLine();
        w.WriteLine("OUTPUT:");
        w.WriteLine("  A single PEM block on stdout (SubjectPublicKeyInfo for RSA or EC).");
        w.WriteLine("  All diagnostics go to stderr.");
        w.WriteLine();
        w.WriteLine("KEY SOURCE (exactly one required):");
        w.WriteLine("      --jwks-url <https-url>          Fetch JWKS directly from this URL.");
        w.WriteLine("      --from-issuer <https-url>       OIDC discovery: fetch <issuer>/.well-known/openid-configuration");
        w.WriteLine("                                      then jwks_uri from the discovered metadata.");
        w.WriteLine("      --jwks-file <path>              Load JWKS from a local file (no network).");
        w.WriteLine();
        w.WriteLine("TOKEN SOURCE:");
        w.WriteLine("      --token-file <path>             Read the JWT from a file. Otherwise read from stdin.");
        w.WriteLine();
        w.WriteLine("NETWORK OPTIONS (ignored for --jwks-file):");
        w.WriteLine("      --bearer-token-file <path>      Send 'Authorization: Bearer <file-contents>'.");
        w.WriteLine("                                      Stripped on any redirect.");
        w.WriteLine("      --bearer-token-discovery        Also send the bearer to the OIDC discovery hop");
        w.WriteLine("                                      (opt-in; default sends only to the jwks_uri hop).");
        w.WriteLine("      --header-file <path>            Extra HTTP headers, one 'Name: value' per line.");
        w.WriteLine("      --ca-bundle <path>              Replace system trust store with this PEM bundle.");
        w.WriteLine("      --timeout-seconds <n>           Per-hop timeout (default 10, max 60).");
        w.WriteLine("      --max-response-bytes <n>        Per-hop body cap (default 262144, max 1048576).");
        w.WriteLine("      --max-redirects <n>             Per-hop redirect cap (default 3, max 5).");
        w.WriteLine("      --require-same-host-jwks-uri    Refuse if jwks_uri host differs from issuer host.");
        w.WriteLine();
        w.WriteLine("PROXY OPTIONS (off by default \u2014 proxy disabled entirely):");
        w.WriteLine("      --proxy <url>                   Use this explicit proxy URL.");
        w.WriteLine("      --use-system-proxy              Honor HTTPS_PROXY / system proxy resolution.");
        w.WriteLine("                                      Mutually exclusive with --proxy.");
        w.WriteLine("      --proxy-default-credentials     Send OS default credentials (NTLM/Kerberos) to proxy.");
        w.WriteLine("      --allow-private-proxy           Permit proxy URLs that resolve to private/loopback IPs");
        w.WriteLine("                                      (for local debug proxies like mitmproxy/Fiddler).");
        w.WriteLine();
        w.WriteLine("GENERAL:");
        w.WriteLine("  -v, --verbose                       Stderr diagnostics. Auth headers are NEVER printed.");
        w.WriteLine("  -h, --help");
        w.WriteLine("  -V, --version");
        w.WriteLine();
        w.WriteLine("EXIT CODES:");
        w.WriteLine("  0  Success \u2014 one PEM on stdout.");
        w.WriteLine("  1  Unexpected error.");
        w.WriteLine("  2  Invalid input (bad URL, bad option, missing file, refused scheme).");
        w.WriteLine("  3  Logical refusal (no matching JWK, ambiguous kid, issuer mismatch,");
        w.WriteLine("     --require-same-host-jwks-uri policy).");
        w.WriteLine("  4  Network error (timeout, TLS failure, oversized response, refused redirect).");
        w.WriteLine();
        w.WriteLine("SECURITY:");
        w.WriteLine("  HTTPS only; no --insecure flag. TLS 1.2 / 1.3 only. HTTP/3 not negotiated.");
        w.WriteLine("  SSRF deny-list (private, loopback, link-local, IPv4-mapped IPv6) applied to every");
        w.WriteLine("  hop. DNS rebinding defended via ConnectCallback (skipped when proxy is in use).");
        w.WriteLine("  Bearer token is byte[]-based and stripped on every redirect, even same-host.");
        w.WriteLine("  No on-disk cache. The CA bundle REPLACES the system trust store when given.");
        w.WriteLine("  Proxy off by default; ambient HTTPS_PROXY is ignored unless --use-system-proxy.");
        w.WriteLine("  This binary is the only JwtDecoder component that opens network sockets.");
        w.WriteLine("  Use it as a separate tool from `jwtdecode`, which is 100% offline by construction.");
    }
}
