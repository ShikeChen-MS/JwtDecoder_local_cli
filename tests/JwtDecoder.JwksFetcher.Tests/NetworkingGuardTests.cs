using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

/// <summary>
/// Phase 1 guard: the JwtDecoder.JwksFetcher assembly must not yet
/// transitively reference any networking type. Phase 2 will introduce
/// <c>System.Net.Http</c> intentionally; this test will be retired then.
/// </summary>
public class NetworkingGuardTests
{
    [Fact]
    public void JwksFetcher_Phase1_HasNoNetworkingReferences()
    {
        var asm = typeof(JwksDocument).Assembly;
        var bad = asm.GetReferencedAssemblies()
            .Where(a => a.Name is not null)
            .Where(a =>
                a.Name!.StartsWith("System.Net.", StringComparison.Ordinal) ||
                a.Name!.StartsWith("System.Web", StringComparison.Ordinal)  ||
                a.Name!.Equals("Microsoft.Extensions.Http", StringComparison.Ordinal))
            .Select(a => a.Name)
            .ToList();

        Assert.True(bad.Count == 0,
            "JwtDecoder.JwksFetcher (Phase 1) must have no networking references yet. " +
            "Found: " + string.Join(", ", bad));
    }
}
