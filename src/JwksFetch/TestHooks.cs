#if JWKSFETCH_TEST_HOOKS
namespace JwksFetch;

/// <summary>
/// Test-only switches consumed by the CLI when building <c>FetcherOptions</c>.
/// </summary>
/// <remarks>
/// This type is COMPILED ONLY when <c>JWKSFETCH_TEST_HOOKS</c> is defined.
/// Test projects set the constant (via their .csproj) so the symbol is
/// reachable for them. The production CLI build does NOT define the constant,
/// so this file produces zero IL in the shipped binary — there is literally
/// no <c>AllowLoopbackForTesting</c> static to flip via reflection,
/// <c>InternalsVisibleTo</c>, or any other means. (Final-review I6.)
/// </remarks>
internal static class TestHooks
{
    /// <summary>
    /// When <c>true</c>, the CLI propagates
    /// <see cref="JwtDecoder.JwksFetcher.FetcherOptions.AllowLoopbackForTesting"/>
    /// so the SSRF policy permits loopback addresses. End-to-end tests use
    /// this to run a local Kestrel HTTPS server bound to 127.0.0.1.
    /// </summary>
    public static bool AllowLoopbackForTesting { get; set; }
}
#endif
