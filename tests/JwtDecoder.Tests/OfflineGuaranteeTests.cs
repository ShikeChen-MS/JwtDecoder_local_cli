using Xunit;

namespace JwtDecoder.Tests;

/// <summary>
/// Durable offline-guarantee assertion: the <c>jwtdecode</c> CLI assembly
/// must NEVER reference a networking assembly. This invariant survives
/// every phase of the JWKS companion work — <c>jwtdecode.exe</c> is the
/// offline trusted binary that users rely on.
/// </summary>
/// <remarks>
/// Companion checks live in <c>JwtDecoder.Core.Tests</c> (Core library) and
/// the CI offline-guarantee pipeline (native AOT binary import inspection).
/// </remarks>
public class OfflineGuaranteeTests
{
    [Fact]
    public void Cli_HasNoNetworkingAssemblyReferences()
    {
        // typeof(JwtDecoder.Program) is internal; use the CLI's Cli class instead.
        var asm = typeof(JwtDecoder.Cli).Assembly;
        var bad = asm.GetReferencedAssemblies()
            .Where(a => a.Name is not null)
            .Where(a =>
                a.Name!.StartsWith("System.Net.", StringComparison.Ordinal) ||
                a.Name!.StartsWith("System.Web", StringComparison.Ordinal)  ||
                a.Name!.Equals("Microsoft.Extensions.Http", StringComparison.Ordinal))
            .Select(a => a.Name)
            .ToList();

        Assert.True(bad.Count == 0,
            "jwtdecode CLI must have no networking assembly references. Found: " +
            string.Join(", ", bad));
    }
}
