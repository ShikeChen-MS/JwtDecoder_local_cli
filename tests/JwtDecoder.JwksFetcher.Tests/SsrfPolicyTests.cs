using System.Net;
using Xunit;

namespace JwtDecoder.JwksFetcher.Tests;

public class SsrfPolicyTests
{
    // ---------- AssertHostnameAllowed ----------

    [Fact]
    public void AssertHostnameAllowed_AcceptsPublicHttps()
    {
        // Should not throw.
        SsrfPolicy.AssertHostnameAllowed(new Uri("https://example.com/path"));
        SsrfPolicy.AssertHostnameAllowed(new Uri("https://8.8.8.8/"));
    }

    [Theory]
    [InlineData("http://example.com/")]
    [InlineData("ftp://example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("data:text/plain,hi")]
    public void AssertHostnameAllowed_RefusesNonHttps(string url)
    {
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri(url)));
    }

    [Theory]
    [InlineData("https://localhost/")]
    [InlineData("https://LOCALHOST/")]
    [InlineData("https://ip6-localhost/")]
    public void AssertHostnameAllowed_RefusesLocalhostHostname(string url)
    {
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri(url)));
    }

    [Theory]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://127.255.255.255/")]
    [InlineData("https://10.0.0.1/")]
    [InlineData("https://10.255.255.255/")]
    [InlineData("https://172.16.0.1/")]
    [InlineData("https://172.31.255.255/")]
    [InlineData("https://192.168.1.1/")]
    [InlineData("https://169.254.169.254/")]
    [InlineData("https://0.0.0.0/")]
    [InlineData("https://100.64.0.1/")]
    public void AssertHostnameAllowed_RefusesIpv4PrivateLiterals(string url)
    {
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri(url)));
    }

    [Theory]
    [InlineData("https://[::1]/")]
    [InlineData("https://[fe80::1]/")]
    [InlineData("https://[fc00::1]/")]
    [InlineData("https://[fd00::1]/")]
    public void AssertHostnameAllowed_RefusesIpv6PrivateLiterals(string url)
    {
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri(url)));
    }

    [Fact]
    public void AssertHostnameAllowed_LoopbackPermittedUnderTestFlag()
    {
        // Should NOT throw with the test escape hatch.
        SsrfPolicy.AssertHostnameAllowed(new Uri("https://127.0.0.1:5000/"), allowLoopbackForTesting: true);
        SsrfPolicy.AssertHostnameAllowed(new Uri("https://[::1]:5000/"), allowLoopbackForTesting: true);
        SsrfPolicy.AssertHostnameAllowed(new Uri("https://localhost:5000/"), allowLoopbackForTesting: true);
    }

    [Fact]
    public void AssertHostnameAllowed_LoopbackEscapeHatchStillRejectsOtherPrivateRanges()
    {
        // Even with the test flag, 10/8 and friends remain refused.
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("https://10.0.0.1/"), allowLoopbackForTesting: true));
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("https://169.254.169.254/"), allowLoopbackForTesting: true));
    }

    // ---------- IsForbiddenAddress (the address-level check used in ConnectCallback) ----------

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("172.20.5.5")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("0.0.0.0")]
    [InlineData("100.64.0.1")]
    public void IsForbiddenAddress_IPv4(string addr)
    {
        Assert.True(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.32.0.1")]            // outside 172.16/12
    [InlineData("100.128.0.1")]           // outside 100.64/10
    public void IsForbiddenAddress_AllowsPublicIPv4(string addr)
    {
        Assert.False(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd00::1")]
    [InlineData("::")]
    public void IsForbiddenAddress_IPv6(string addr)
    {
        Assert.True(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    [Fact]
    public void IsForbiddenAddress_AllowsPublicIPv6()
    {
        Assert.False(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse("2606:4700:4700::1111"))); // Cloudflare
    }

    [Theory]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("::ffff:192.168.1.1")]
    public void IsForbiddenAddress_UnmapsIPv4MappedIPv6(string addr)
    {
        Assert.True(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    [Fact]
    public void IsForbiddenAddress_AllowsLoopbackUnderTestFlag()
    {
        Assert.False(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse("127.0.0.1"), allowLoopbackForTesting: true));
        Assert.False(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse("::1"), allowLoopbackForTesting: true));
        Assert.True( SsrfPolicy.IsForbiddenAddress(IPAddress.Parse("10.0.0.1"), allowLoopbackForTesting: true));
    }
}
