using JwtDecoder;
using Xunit;

namespace JwtDecoder.Tests;

public class CliParseTests
{
    // -----------------------------------------------------------------
    // No-op / discovery flags
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("-h")]
    [InlineData("--help")]
    public void Help_flag_sets_Help_true(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { flag });
        Assert.Null(err);
        Assert.NotNull(opts);
        Assert.True(opts!.Help);
    }

    [Theory]
    [InlineData("-v")]
    [InlineData("--version")]
    public void Version_flag_sets_Version_true(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { flag });
        Assert.Null(err);
        Assert.True(opts!.Version);
    }

    [Fact]
    public void VersionString_is_non_empty()
    {
        Assert.False(string.IsNullOrWhiteSpace(Cli.VersionString));
    }

    // -----------------------------------------------------------------
    // Positional token + --file
    // -----------------------------------------------------------------

    [Fact]
    public void Positional_token_is_captured()
    {
        var (opts, err) = Cli.Parse(new[] { "eyJabc.def.ghi" });
        Assert.Null(err);
        Assert.Equal("eyJabc.def.ghi", opts!.Token);
        Assert.Null(opts.TokenFile);
    }

    [Fact]
    public void File_flag_captures_path()
    {
        var (opts, err) = Cli.Parse(new[] { "--file", "C:\\tmp\\token.jwt" });
        Assert.Null(err);
        Assert.Equal("C:\\tmp\\token.jwt", opts!.TokenFile);
        Assert.Null(opts.Token);
    }

    [Fact]
    public void File_without_value_errors()
    {
        var (opts, err) = Cli.Parse(new[] { "--file" });
        Assert.Null(opts);
        Assert.NotNull(err);
        Assert.Contains("--file requires", err!);
    }

    [Fact]
    public void File_specified_twice_errors()
    {
        var (opts, err) = Cli.Parse(new[] { "--file", "a", "--file", "b" });
        Assert.Null(opts);
        Assert.Contains("more than once", err!);
    }

    [Fact]
    public void Positional_plus_File_is_rejected()
    {
        var (opts, err) = Cli.Parse(new[] { "tok", "--file", "p" });
        Assert.Null(opts);
        Assert.Contains("either a positional token OR --file", err!);
    }

    [Fact]
    public void Two_positional_tokens_rejected()
    {
        var (opts, err) = Cli.Parse(new[] { "tok1", "tok2" });
        Assert.Null(opts);
        Assert.Contains("more than one token", err!);
    }

    // -----------------------------------------------------------------
    // --verify / --key-file
    // -----------------------------------------------------------------

    [Fact]
    public void Verify_and_keyfile_pair_succeeds()
    {
        var (opts, err) = Cli.Parse(new[] { "tok", "--verify", "--key-file", "k" });
        Assert.Null(err);
        Assert.True(opts!.Verify);
        Assert.Equal("k", opts.KeyFile);
    }

    [Fact]
    public void Verify_without_keyfile_errors()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--verify" });
        Assert.Contains("--verify requires --key-file", err!);
    }

    [Fact]
    public void Keyfile_without_verify_errors()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--key-file", "k" });
        Assert.Contains("--key-file is only meaningful with --verify", err!);
    }

    [Fact]
    public void Keyfile_without_value_errors()
    {
        var (_, err) = Cli.Parse(new[] { "--key-file" });
        Assert.Contains("--key-file requires", err!);
    }

    [Fact]
    public void Keyfile_specified_twice_errors()
    {
        var (_, err) = Cli.Parse(new[] { "--verify", "--key-file", "a", "--key-file", "b" });
        Assert.Contains("more than once", err!);
    }

    // -----------------------------------------------------------------
    // --detailed
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("-d")]
    [InlineData("--detailed")]
    public void Detailed_flag_is_recognized(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { "tok", flag });
        Assert.Null(err);
        Assert.True(opts!.Detailed);
    }

    // -----------------------------------------------------------------
    // --query (new) and --raw (new)
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("-q")]
    [InlineData("--query")]
    public void Query_flag_captures_path(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { "tok", flag, "payload.sub" });
        Assert.Null(err);
        Assert.Equal("payload.sub", opts!.Query);
        Assert.False(opts.Raw);
    }

    [Fact]
    public void Query_supports_comma_separated_paths_as_single_value()
    {
        var (opts, err) = Cli.Parse(new[] { "tok", "--query", "payload.sub,header.alg" });
        Assert.Null(err);
        Assert.Equal("payload.sub,header.alg", opts!.Query);
    }

    [Fact]
    public void Query_without_value_errors()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--query" });
        Assert.Contains("--query requires", err!);
    }

    [Fact]
    public void Query_specified_twice_errors()
    {
        // Multi-path queries use comma separation in a single --query arg, not repeated flags.
        var (_, err) = Cli.Parse(new[] { "tok", "--query", "payload.sub", "--query", "header.alg" });
        Assert.Contains("more than once", err!);
    }

    [Fact]
    public void Raw_without_Query_errors()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--raw" });
        Assert.Contains("--raw is only meaningful with --query", err!);
    }

    [Fact]
    public void Raw_with_Query_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[] { "tok", "--query", "sub", "--raw" });
        Assert.Null(err);
        Assert.True(opts!.Raw);
        Assert.Equal("sub", opts.Query);
    }

    [Fact]
    public void Query_combined_with_Detailed_is_rejected()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--query", "sub", "--detailed" });
        Assert.Contains("--query and --detailed cannot be combined", err!);
    }

    [Fact]
    public void Query_combined_with_Verify_and_KeyFile_is_allowed()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "tok", "--query", "sub", "--verify", "--key-file", "k"
        });
        Assert.Null(err);
        Assert.True(opts!.Verify);
        Assert.Equal("k", opts.KeyFile);
        Assert.Equal("sub", opts.Query);
    }

    // -----------------------------------------------------------------
    // Unknown options and misc
    // -----------------------------------------------------------------

    [Fact]
    public void Unknown_option_is_rejected()
    {
        var (_, err) = Cli.Parse(new[] { "tok", "--definitely-not-an-option" });
        Assert.Contains("unknown option", err!);
    }

    [Fact]
    public void No_args_returns_empty_options_without_error()
    {
        // Program.cs handles "no token" as a runtime error AFTER also looking at stdin; the
        // parser itself must succeed so the help-on-stdin path can take over.
        var (opts, err) = Cli.Parse(Array.Empty<string>());
        Assert.Null(err);
        Assert.NotNull(opts);
        Assert.Null(opts!.Token);
        Assert.Null(opts.TokenFile);
        Assert.False(opts.Verify);
        Assert.Null(opts.Query);
    }
}
