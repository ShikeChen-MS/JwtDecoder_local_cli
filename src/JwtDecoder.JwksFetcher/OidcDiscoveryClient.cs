namespace JwtDecoder.JwksFetcher;

/// <summary>The outcome of an end-to-end OIDC discovery + JWKS fetch.</summary>
/// <param name="JwksDocument">The raw bytes of the JWKS document.</param>
/// <param name="JwksUri">The URL the JWKS was retrieved from.</param>
/// <param name="CrossHostJwksUri"><c>true</c> if the <c>jwks_uri</c> host
/// differs from the requested issuer's host. Operators typically surface a
/// stderr warning when this is set.</param>
public sealed record OidcDiscoveryFetchResult(byte[] JwksDocument, Uri JwksUri, bool CrossHostJwksUri);

/// <summary>
/// Performs the two-hop OIDC discovery + JWKS retrieval flow.
/// </summary>
/// <remarks>
/// Layered on top of <see cref="JwksClient"/>; uses the same hardening
/// (HTTPS only, SSRF, redirect cap, CA bundle, proxy). Each hop is fetched
/// independently with its own <see cref="FetcherOptions"/> limits.
/// <para>
/// Bearer token attachment follows the round-2 review decision: the bearer
/// is attached to the JWKS request only. It reaches the discovery request
/// only when <see cref="FetcherOptions.SendBearerToDiscovery"/> is <c>true</c>.
/// </para>
/// </remarks>
public static class OidcDiscoveryClient
{
    /// <summary>Fetch <c>/.well-known/openid-configuration</c> from
    /// <paramref name="issuer"/>, then fetch <c>jwks_uri</c>.</summary>
    /// <exception cref="ArgumentNullException">If either argument is null.</exception>
    /// <exception cref="InvalidDataException">If any validation step fails.</exception>
    public static async Task<OidcDiscoveryFetchResult> DiscoverAndFetchJwksAsync(
        Uri issuer, FetcherOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(options);

        Uri discoveryUrl = OidcDiscoveryDocument.BuildDiscoveryUrl(issuer);

        // Bearer scoping: by default, do NOT send bearer on discovery.
        var discoveryOpts = options.SendBearerToDiscovery
            ? options
            : new FetcherOptions
            {
                Timeout = options.Timeout,
                MaxResponseBytes = options.MaxResponseBytes,
                MaxRedirects = options.MaxRedirects,
                CaBundlePath = options.CaBundlePath,
                BearerTokenBytes = null,
                ExtraHeaders = options.ExtraHeaders,
                ProxyMode = options.ProxyMode,
                ProxyUri = options.ProxyUri,
                ProxyDefaultCredentials = options.ProxyDefaultCredentials,
                AllowPrivateProxy = options.AllowPrivateProxy,
                AllowLoopbackForTesting = options.AllowLoopbackForTesting,
                SendBearerToDiscovery = false,
            };

        FetchResult metadataFetch = await JwksClient.FetchAsync(discoveryUrl, discoveryOpts, ct).ConfigureAwait(false);
        DiscoveryResult discovery = OidcDiscoveryDocument.Parse(metadataFetch.Body, issuer);

        FetchResult jwksFetch = await JwksClient.FetchAsync(discovery.JwksUri, options, ct).ConfigureAwait(false);
        return new OidcDiscoveryFetchResult(jwksFetch.Body, jwksFetch.FinalUri, discovery.CrossHostJwksUri);
    }
}
