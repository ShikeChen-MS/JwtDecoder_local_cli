using Xunit;

namespace JwksFetch.Tests;

public class ScaffoldTests
{
    [Fact]
    public void Scaffold_Builds()
    {
        // Phase 0: ensures the test project compiles and references the
        // jwksfetch assembly. Real tests land in Phase 4.
        Assert.Equal("jwksfetch", typeof(Program).Assembly.GetName().Name);
    }
}
