using JwtDecoder.JwksFetcher;
using Xunit;

namespace JwksFetch.Tests;

public class CliParseTests
{
    // ---------- discovery flags ----------

    [Theory]
    [InlineData("-h")]
    [InlineData("--help")]
    public void Help_flag_sets_Help_true(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { flag });
        Assert.Null(err);
        Assert.True(opts!.Help);
    }

    [Theory]
    [InlineData("-V")]
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

    // ---------- key-source mutual exclusion ----------

    [Fact]
    public void Missing_key_source_is_error()
    {
        var (opts, err) = Cli.Parse(new[] { "--token-file", "t" });
        Assert.Null(opts);
        Assert.Contains("--jwks-url", err!);
    }

    [Fact]
    public void Two_key_sources_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--jwks-file", "k.json",
        });
        Assert.Contains("mutually exclusive", err!);
    }

    [Fact]
    public void All_three_key_sources_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--from-issuer", "https://example.com",
            "--jwks-file", "k.json",
        });
        Assert.Contains("mutually exclusive", err!);
    }

    [Fact]
    public void JwksUrl_alone_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[] { "--jwks-url", "https://example.com/keys" });
        Assert.Null(err);
        Assert.Equal(new Uri("https://example.com/keys"), opts!.JwksUrl);
    }

    [Fact]
    public void FromIssuer_alone_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[] { "--from-issuer", "https://login.example.com/tenant" });
        Assert.Null(err);
        Assert.Equal(new Uri("https://login.example.com/tenant"), opts!.FromIssuer);
    }

    [Fact]
    public void JwksFile_alone_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[] { "--jwks-file", "C:\\tmp\\k.json" });
        Assert.Null(err);
        Assert.Equal("C:\\tmp\\k.json", opts!.JwksFile);
    }

    [Fact]
    public void JwksUrl_invalid_is_error()
    {
        var (_, err) = Cli.Parse(new[] { "--jwks-url", "not-a-url" });
        Assert.Contains("not a valid URL", err!);
    }

    [Fact]
    public void JwksUrl_specified_twice_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://a.example/",
            "--jwks-url", "https://b.example/",
        });
        Assert.Contains("more than once", err!);
    }

    // ---------- jwks-file ignores network options ----------

    [Theory]
    [InlineData("--bearer-token-file", "f")]
    [InlineData("--header-file", "f")]
    [InlineData("--ca-bundle", "f")]
    public void JwksFile_with_network_option_is_error(string opt, string val)
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-file", "k.json",
            opt, val,
        });
        Assert.NotNull(err);
        Assert.Contains("meaningless with --jwks-file", err!);
    }

    [Fact]
    public void JwksFile_with_proxy_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-file", "k.json",
            "--proxy", "http://corp.example:8080",
        });
        Assert.Contains("meaningless with --jwks-file", err!);
    }

    // ---------- proxy options ----------

    [Fact]
    public void Proxy_and_use_system_proxy_are_mutually_exclusive()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--proxy", "http://corp.example:8080",
            "--use-system-proxy",
        });
        Assert.Contains("mutually exclusive", err!);
    }

    [Fact]
    public void Explicit_proxy_sets_ProxyMode_Explicit()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--proxy", "http://corp.example:8080",
        });
        Assert.Null(err);
        Assert.Equal(ProxyMode.Explicit, opts!.ProxyMode);
        Assert.Equal(new Uri("http://corp.example:8080"), opts.ProxyUri);
    }

    [Fact]
    public void UseSystemProxy_sets_ProxyMode_System()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--use-system-proxy",
        });
        Assert.Null(err);
        Assert.Equal(ProxyMode.System, opts!.ProxyMode);
    }

    [Fact]
    public void ProxyDefaultCredentials_without_proxy_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--proxy-default-credentials",
        });
        Assert.Contains("--proxy-default-credentials", err!);
    }

    [Fact]
    public void AllowPrivateProxy_without_proxy_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--allow-private-proxy",
        });
        Assert.Contains("--allow-private-proxy", err!);
    }

    [Fact]
    public void Proxy_with_default_credentials_and_allow_private_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--proxy", "http://corp.example:8080",
            "--proxy-default-credentials",
            "--allow-private-proxy",
        });
        Assert.Null(err);
        Assert.True(opts!.ProxyDefaultCredentials);
        Assert.True(opts.AllowPrivateProxy);
    }

    // ---------- bearer / discovery interplay ----------

    [Fact]
    public void BearerTokenDiscovery_without_bearer_file_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--bearer-token-discovery",
        });
        Assert.Contains("--bearer-token-discovery requires --bearer-token-file", err!);
    }

    [Fact]
    public void BearerTokenFile_alone_is_accepted_with_jwks_url()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--bearer-token-file", "t",
        });
        Assert.Null(err);
        Assert.Equal("t", opts!.BearerTokenFile);
        Assert.False(opts.BearerTokenDiscovery);
    }

    // ---------- numeric options bounds ----------

    [Theory]
    [InlineData("--timeout-seconds", "0")]
    [InlineData("--timeout-seconds", "61")]
    [InlineData("--timeout-seconds", "abc")]
    [InlineData("--max-response-bytes", "0")]
    [InlineData("--max-redirects", "-1")]
    [InlineData("--max-redirects", "6")]
    public void Numeric_option_out_of_range_is_error(string opt, string val)
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            opt, val,
        });
        Assert.NotNull(err);
    }

    [Fact]
    public void Numeric_options_within_range_are_accepted()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--timeout-seconds", "30",
            "--max-response-bytes", "131072",
            "--max-redirects", "1",
        });
        Assert.Null(err);
        Assert.Equal(30, opts!.TimeoutSeconds);
        Assert.Equal(131072, opts.MaxResponseBytes);
        Assert.Equal(1, opts.MaxRedirects);
    }

    // ---------- require-same-host-jwks-uri ----------

    [Fact]
    public void RequireSameHostJwksUri_without_from_issuer_is_error()
    {
        var (_, err) = Cli.Parse(new[]
        {
            "--jwks-url", "https://example.com/k",
            "--require-same-host-jwks-uri",
        });
        Assert.Contains("--require-same-host-jwks-uri", err!);
    }

    [Fact]
    public void RequireSameHostJwksUri_with_from_issuer_is_accepted()
    {
        var (opts, err) = Cli.Parse(new[]
        {
            "--from-issuer", "https://login.example.com",
            "--require-same-host-jwks-uri",
        });
        Assert.Null(err);
        Assert.True(opts!.RequireSameHostJwksUri);
    }

    // ---------- unknown options ----------

    [Fact]
    public void Unknown_option_is_error()
    {
        var (_, err) = Cli.Parse(new[] { "--jwks-url", "https://example.com/k", "--whatever" });
        Assert.Contains("unknown option", err!);
    }

    // ---------- verbose ----------

    [Theory]
    [InlineData("-v")]
    [InlineData("--verbose")]
    public void Verbose_flag_sets_Verbose(string flag)
    {
        var (opts, err) = Cli.Parse(new[] { "--jwks-url", "https://example.com/k", flag });
        Assert.Null(err);
        Assert.True(opts!.Verbose);
    }
}
