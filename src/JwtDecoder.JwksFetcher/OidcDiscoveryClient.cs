namespace JwtDecoder.JwksFetcher;

/// <summary>The outcome of an end-to-end OIDC discovery + JWKS fetch.</summary>
/// <param name="JwksDocument">The raw bytes of the JWKS document.</param>
/// <param name="JwksUri">The URL the JWKS was retrieved from.</param>
/// <param name="CrossHostJwksUri"><c>true</c> if the <c>jwks_uri</c> host
/// differs from the requested issuer's host. Operators typically surface a
/// stderr warning when this is set.</param>
public sealed record OidcDiscoveryFetchResult(byte[] JwksDocument, Uri JwksUri, bool CrossHostJwksUri);

/// <summary>Caller-supplied policy hooks applied to the OIDC discovery flow.</summary>
public sealed class OidcDiscoveryOptions
{
    /// <summary>
    /// When <c>true</c>, the <c>jwks_uri</c> from the OIDC metadata MUST share its
    /// host with the requested issuer. If it does not, the JWKS request is
    /// <b>not made</b> — refusing here is critical because the bearer token (if
    /// any) would otherwise leak to the cross-host endpoint before the caller
    /// got a chance to see <see cref="OidcDiscoveryFetchResult.CrossHostJwksUri"/>.
    /// </summary>
    public bool RequireSameHostJwksUri { get; init; }
}

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
/// <para>
/// When the caller opts into <see cref="OidcDiscoveryOptions.RequireSameHostJwksUri"/>,
/// the cross-host check is enforced <b>before</b> the JWKS fetch is dispatched
/// so the bearer token never reaches a host the caller meant to refuse
/// (final-review item B2).
/// </para>
/// </remarks>
public static class OidcDiscoveryClient
{
    /// <summary>Fetch <c>/.well-known/openid-configuration</c> from
    /// <paramref name="issuer"/>, then fetch <c>jwks_uri</c>.</summary>
    /// <exception cref="ArgumentNullException">If <paramref name="issuer"/> or
    /// <paramref name="options"/> is null.</exception>
    /// <exception cref="InvalidDataException">If any validation step fails,
    /// including the same-host policy when enabled.</exception>
    public static async Task<OidcDiscoveryFetchResult> DiscoverAndFetchJwksAsync(
        Uri issuer,
        FetcherOptions options,
        OidcDiscoveryOptions? discoveryOptions = null,
        CancellationToken ct = default)
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

        // PRE-FETCH same-host enforcement. Critical: this MUST happen before
        // JwksClient.FetchAsync below, or the bearer token (when supplied) will
        // already have been sent to the cross-host endpoint. Final-review B2.
        if (discoveryOptions is { RequireSameHostJwksUri: true } && discovery.CrossHostJwksUri)
        {
            throw new InvalidDataException(
                $"OIDC discovery: jwks_uri host '{discovery.JwksUri.Host}' differs from issuer host " +
                $"'{issuer.Host}'. Refusing to fetch under RequireSameHostJwksUri policy.");
        }

        FetchResult jwksFetch = await JwksClient.FetchAsync(discovery.JwksUri, options, ct).ConfigureAwait(false);
        return new OidcDiscoveryFetchResult(jwksFetch.Body, jwksFetch.FinalUri, discovery.CrossHostJwksUri);
    }
}
