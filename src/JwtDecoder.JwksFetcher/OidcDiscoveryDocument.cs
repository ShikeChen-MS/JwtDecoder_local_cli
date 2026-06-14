using System.Text.Json;

namespace JwtDecoder.JwksFetcher;

/// <summary>The validated outcome of parsing an OIDC discovery document.</summary>
/// <param name="JwksUri">The resolved JWKS URL from the metadata document.</param>
/// <param name="CrossHostJwksUri"><c>true</c> if the <c>jwks_uri</c> host differs from the
/// requested issuer's host (a defense-in-depth signal for the operator; not a refusal).</param>
public sealed record DiscoveryResult(Uri JwksUri, bool CrossHostJwksUri);

/// <summary>
/// Parses and validates an OpenID Connect Discovery 1.0 metadata document,
/// returning only the <c>jwks_uri</c>.
/// </summary>
/// <remarks>
/// This type performs no network I/O. It validates a metadata response that
/// the network layer has already fetched. Validation rules:
/// <list type="bullet">
/// <item>Strict JSON: <c>MaxDepth = 64</c>, no comments, no trailing commas,
/// recursive duplicate-property rejection.</item>
/// <item>Overall size cap of <see cref="MaxMetadataBytes"/>.</item>
/// <item>Required <c>issuer</c> field MUST equal the requested issuer URL
/// after canonicalization (lowercase host, default port stripped, single
/// trailing slash stripped from path) — per OIDC Discovery 1.0 §4.3.</item>
/// <item>Required <c>jwks_uri</c> field MUST parse as an absolute HTTPS URL.</item>
/// <item>Cross-host <c>jwks_uri</c> is allowed (Google uses this pattern) but
/// surfaced in <see cref="DiscoveryResult.CrossHostJwksUri"/> so callers can
/// log a stderr warning.</item>
/// </list>
/// </remarks>
public static class OidcDiscoveryDocument
{
    /// <summary>OIDC metadata documents in production are usually &lt; 4 KiB. 256 KiB is a generous bound.</summary>
    public const int MaxMetadataBytes = 256 * 1024;

    /// <summary>Suffix appended to an issuer URL to form the discovery URL.</summary>
    public const string WellKnownPath = "/.well-known/openid-configuration";

    /// <summary>Parse a metadata document fetched from <paramref name="requestedIssuer"/>.</summary>
    /// <exception cref="ArgumentNullException">If either argument is null.</exception>
    /// <exception cref="InvalidDataException">Invalid, oversized, issuer-mismatched, or missing required fields.</exception>
    public static DiscoveryResult Parse(ReadOnlySpan<byte> metadataJson, Uri requestedIssuer)
    {
        ArgumentNullException.ThrowIfNull(requestedIssuer);

        if (metadataJson.Length > MaxMetadataBytes)
            throw new InvalidDataException($"OIDC metadata document exceeds maximum size of {MaxMetadataBytes:N0} bytes.");
        if (metadataJson.IsEmpty)
            throw new InvalidDataException("OIDC metadata document is empty.");

        RejectDuplicateKeysRecursive(metadataJson, "OIDC metadata");

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(metadataJson.ToArray(), new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = 64,
            });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("OIDC metadata document is not valid JSON: " + ex.Message, ex);
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("OIDC metadata root must be a JSON object.");

            // --- issuer ---
            if (!doc.RootElement.TryGetProperty("issuer", out var issuerEl) || issuerEl.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("OIDC metadata is missing required string member 'issuer'.");
            string issuerStr = issuerEl.GetString() ?? "";
            if (issuerStr.Length == 0)
                throw new InvalidDataException("OIDC metadata 'issuer' is empty.");
            if (!Uri.TryCreate(issuerStr, UriKind.Absolute, out var metadataIssuerUri))
                throw new InvalidDataException($"OIDC metadata 'issuer' is not a valid absolute URL: '{issuerStr}'.");

            string canonRequested = CanonicalIssuerString(requestedIssuer);
            string canonMetadata = CanonicalIssuerString(metadataIssuerUri);
            if (!string.Equals(canonRequested, canonMetadata, StringComparison.Ordinal))
                throw new InvalidDataException(
                    $"OIDC issuer mismatch: requested '{canonRequested}' but metadata claims '{canonMetadata}'. " +
                    "Refusing — the issuer field MUST equal the requested URL per OIDC Discovery 1.0 §4.3.");

            // --- jwks_uri ---
            if (!doc.RootElement.TryGetProperty("jwks_uri", out var jwksUriEl) || jwksUriEl.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("OIDC metadata is missing required string member 'jwks_uri'.");
            string jwksUriStr = jwksUriEl.GetString() ?? "";
            if (jwksUriStr.Length == 0)
                throw new InvalidDataException("OIDC metadata 'jwks_uri' is empty.");
            if (!Uri.TryCreate(jwksUriStr, UriKind.Absolute, out var jwksUri))
                throw new InvalidDataException($"OIDC metadata 'jwks_uri' is not a valid absolute URL: '{jwksUriStr}'.");
            if (!string.Equals(jwksUri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"OIDC metadata 'jwks_uri' must use https; got '{jwksUri.Scheme}'.");

            bool crossHost = !string.Equals(
                jwksUri.Host,
                requestedIssuer.Host,
                StringComparison.OrdinalIgnoreCase);

            return new DiscoveryResult(jwksUri, crossHost);
        }
    }

    /// <summary>
    /// Build the discovery URL for an issuer by appending
    /// <c>/.well-known/openid-configuration</c> per OIDC Discovery 1.0 §4.1.
    /// </summary>
    /// <remarks>
    /// Refuses inputs that already contain <c>/.well-known/</c> in the path to
    /// avoid ambiguity ("what did the user mean?"). If users need a custom
    /// discovery URL, they should use <c>--jwks-url</c> directly.
    /// </remarks>
    /// <exception cref="ArgumentNullException">If <paramref name="issuer"/> is null.</exception>
    /// <exception cref="InvalidDataException">If the issuer is not HTTPS or already contains a well-known path.</exception>
    public static Uri BuildDiscoveryUrl(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        if (!string.Equals(issuer.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"OIDC issuer must use https; got '{issuer.Scheme}'.");
        if (issuer.AbsolutePath.Contains("/.well-known/", StringComparison.Ordinal))
            throw new InvalidDataException(
                "OIDC issuer must NOT contain '/.well-known/' in its path. " +
                "Pass the bare issuer identifier (e.g. 'https://example.com/tenant'); " +
                "the tool appends '/.well-known/openid-configuration' itself.");

        // Append /.well-known/openid-configuration, collapsing exactly one slash.
        string basePath = issuer.AbsolutePath;
        string joined = basePath.EndsWith('/')
            ? basePath + WellKnownPath.TrimStart('/')
            : basePath + WellKnownPath;

        var b = new UriBuilder(issuer.Scheme, issuer.Host, issuer.Port, joined);
        return b.Uri;
    }

    /// <summary>Canonicalize an issuer URL for byte-equal comparison.</summary>
    /// <remarks>
    /// Lowercases host, strips default 443/80 port, strips exactly one trailing
    /// slash from the path (preserving the root "/"). Does not touch query or
    /// fragment because issuer identifiers must not carry them per RFC 8414 §2.
    /// </remarks>
    public static string CanonicalIssuerString(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        string scheme = uri.Scheme.ToLowerInvariant();
        string host = uri.Host.ToLowerInvariant();
        int port = uri.Port;
        bool isDefaultPort =
            (scheme == "https" && port == 443) ||
            (scheme == "http" && port == 80);
        string portPart = isDefaultPort ? "" : $":{port}";
        string path = uri.AbsolutePath;
        // Strip a single trailing slash. Root "/" canonicalizes to "" so that
        // "https://example.com" and "https://example.com/" produce the same
        // string. Path-style issuers ("/realms/foo/") become "/realms/foo".
        if (path.EndsWith('/')) path = path[..^1];
        return $"{scheme}://{host}{portPart}{path}";
    }

    private static void RejectDuplicateKeysRecursive(ReadOnlySpan<byte> jsonBytes, string contextName)
    {
        var reader = new Utf8JsonReader(jsonBytes, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 64,
        });

        var stack = new Stack<HashSet<string>>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        stack.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.EndObject:
                        if (stack.Count > 0) stack.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        if (stack.Count > 0)
                        {
                            string name = reader.GetString() ?? "";
                            if (!stack.Peek().Add(name))
                                throw new InvalidDataException($"{contextName} contains duplicate JSON property '{name}'.");
                        }
                        break;
                }
            }
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"{contextName} is not valid JSON: " + ex.Message, ex);
        }
    }
}
