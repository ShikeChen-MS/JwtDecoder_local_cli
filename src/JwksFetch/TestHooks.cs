namespace JwksFetch;

/// <summary>
/// Test-only switches consumed by the CLI when building <c>FetcherOptions</c>.
/// </summary>
/// <remarks>
/// The properties are <c>internal</c> and the type itself is only reachable
/// from <c>JwksFetch.Tests</c> via <c>InternalsVisibleTo</c>. Production
/// callers cannot flip these from outside the assembly without reflection.
/// </remarks>
internal static class TestHooks
{
    /// <summary>
    /// When <c>true</c>, the CLI propagates
    /// <see cref="JwtDecoder.JwksFetcher.FetcherOptions.AllowLoopbackForTesting"/>
    /// so the SSRF policy permits loopback addresses. End‑to‑end tests use
    /// this to run a local Kestrel HTTPS server bound to 127.0.0.1.
    /// </summary>
    public static bool AllowLoopbackForTesting { get; set; }
}
