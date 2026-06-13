using System.Reflection;

namespace JwtDecoder.Core.Tests;

/// <summary>
/// Resolves files in the repository's <c>samples/</c> directory at test time.
/// </summary>
/// <remarks>
/// The csproj copies <c>../../samples/**/*</c> next to the test assembly under
/// a <c>samples</c> subdirectory; this helper finds that copy by reflecting on
/// the test assembly's location.
/// </remarks>
internal static class TestSamples
{
    public static string Dir { get; } = System.IO.Path.Combine(
        System.IO.Path.GetDirectoryName(typeof(TestSamples).Assembly.Location)!,
        "samples");

    public static string Path(string fileName)
    {
        string p = System.IO.Path.Combine(Dir, fileName);
        if (!File.Exists(p))
            throw new FileNotFoundException(
                $"Sample file not found: {p}. Did the test project's <None Include=\"..\\..\\samples\\**\\*\" /> item lose its CopyToOutputDirectory?");
        return p;
    }

    public static string ReadText(string fileName) => File.ReadAllText(Path(fileName)).Trim();
}
