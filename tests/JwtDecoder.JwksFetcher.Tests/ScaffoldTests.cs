using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class ScaffoldTests
{
    [Fact]
    public void Scaffold_Builds()
    {
        // Phase 0: ensures the test project compiles and references the
        // JwtDecoder.JwksFetcher assembly. Real tests land in Phase 1.
        Assert.Equal("JwtDecoder.JwksFetcher", typeof(AssemblyMarker).Assembly.GetName().Name);
    }
}
