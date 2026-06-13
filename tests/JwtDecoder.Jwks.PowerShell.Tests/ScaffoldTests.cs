using Xunit;

namespace JwtDecoder.Jwks.PowerShell.Tests;

public class ScaffoldTests
{
    [Fact]
    public void Scaffold_Builds()
    {
        // Phase 0: ensures the test project compiles and references the
        // JwtDecoder.Jwks.PowerShell assembly. Real tests land in Phase 5.
        Assert.Equal("JwtDecoder.Jwks.PowerShell", typeof(AssemblyMarker).Assembly.GetName().Name);
    }
}
