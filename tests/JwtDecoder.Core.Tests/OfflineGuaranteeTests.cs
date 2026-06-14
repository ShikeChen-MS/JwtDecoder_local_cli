using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

/// <summary>
/// Durable offline-guarantee assertion: <c>JwtDecoder.Core</c> must NEVER
/// reference a networking assembly. This invariant survives every phase
/// of the JWKS companion work — Core is the trusted, offline-by-construction
/// foundation that all other components build on.
/// </summary>
/// <remarks>
/// Companion checks live in <c>JwtDecoder.Tests</c> (CLI assembly) and the
/// CI offline-guarantee pipeline (native binary import inspection).
/// </remarks>
public class OfflineGuaranteeTests
{
    [Fact]
    public void Core_HasNoNetworkingAssemblyReferences()
    {
        var asm = typeof(Jwt).Assembly;
        var bad = asm.GetReferencedAssemblies()
            .Where(a => a.Name is not null)
            .Where(a =>
                a.Name!.StartsWith("System.Net.", StringComparison.Ordinal) ||
                a.Name!.StartsWith("System.Web", StringComparison.Ordinal)  ||
                a.Name!.Equals("Microsoft.Extensions.Http", StringComparison.Ordinal))
            .Select(a => a.Name)
            .ToList();

        Assert.True(bad.Count == 0,
            "JwtDecoder.Core must have no networking assembly references. Found: " +
            string.Join(", ", bad));
    }
}
