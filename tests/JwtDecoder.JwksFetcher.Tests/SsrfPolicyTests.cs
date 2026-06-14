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

    // ---------- Round-6 #5: extended IPv4 deny-list ----------
    // 224/4 multicast, 240/4 reserved+broadcast, IETF protocol-assignment
    // (192.0.0/24), TEST-NET-1/2/3, and 198.18/15 benchmarking subnets.
    // Most aren't practical TCP attack vectors but DNS rebinding to a
    // misconfigured network with routed TEST-NET could land here.

    [Theory]
    [InlineData("224.0.0.1")]            // multicast — IGMP all-systems
    [InlineData("239.255.255.250")]      // SSDP
    [InlineData("240.0.0.1")]            // class E reserved
    [InlineData("255.255.255.255")]      // limited broadcast
    [InlineData("192.0.0.1")]            // IETF protocol assignments
    [InlineData("192.0.2.1")]            // TEST-NET-1
    [InlineData("198.51.100.1")]         // TEST-NET-2
    [InlineData("203.0.113.1")]          // TEST-NET-3
    [InlineData("198.18.0.1")]           // benchmarking
    [InlineData("198.19.255.255")]       // benchmarking (upper edge of 198.18/15)
    public void IsForbiddenAddress_ExtendedDenyList_IPv4(string addr)
    {
        Assert.True(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    [Theory]
    [InlineData("192.0.1.1")]            // adjacent to 192.0.0/24, must stay allowed
    [InlineData("192.0.3.1")]            // adjacent to 192.0.2/24 (TEST-NET-1), must stay allowed
    [InlineData("198.50.100.1")]         // adjacent to 198.51.100/24, must stay allowed
    [InlineData("198.17.255.255")]       // just below 198.18/15
    [InlineData("198.20.0.1")]           // just above 198.18/15
    [InlineData("203.0.114.1")]          // adjacent to 203.0.113/24
    [InlineData("223.255.255.255")]      // just below 224/4 multicast
    public void IsForbiddenAddress_ExtendedDenyList_DoesNotOverreach(string addr)
    {
        Assert.False(SsrfPolicy.IsForbiddenAddress(IPAddress.Parse(addr)));
    }

    // ---------- Round-6 #4: requireHttps:false overload ----------

    [Fact]
    public void AssertHostnameAllowed_RequireHttpsFalse_AcceptsHttpPublicUrl()
    {
        // Used on the proxy-validation path: the scheme has already been
        // validated as http or https; we just need the deny-list check.
        // Public IP / public hostname must not throw.
        SsrfPolicy.AssertHostnameAllowed(new Uri("http://corp-proxy.example.com:8080/"),
            allowLoopbackForTesting: false, requireHttps: false);
        SsrfPolicy.AssertHostnameAllowed(new Uri("http://8.8.8.8:8080/"),
            allowLoopbackForTesting: false, requireHttps: false);
    }

    [Fact]
    public void AssertHostnameAllowed_RequireHttpsFalse_StillRefusesPrivateIp()
    {
        // The deny-list is the WHOLE point of this code path; loosening
        // the scheme check must not loosen the IP check.
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("http://127.0.0.1:8080/"),
                allowLoopbackForTesting: false, requireHttps: false));
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("http://169.254.169.254:8080/"),
                allowLoopbackForTesting: false, requireHttps: false));
        Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("http://localhost:8080/"),
                allowLoopbackForTesting: false, requireHttps: false));
    }

    [Fact]
    public void AssertHostnameAllowed_RequireHttpsTrue_DefaultStillRefusesHttp()
    {
        // Default-value behaviour unchanged: the http URL is refused by
        // the scheme check before we even look at the host.
        var ex = Assert.Throws<InvalidDataException>(() =>
            SsrfPolicy.AssertHostnameAllowed(new Uri("http://8.8.8.8/")));
        Assert.Contains("non-HTTPS", ex.Message);
    }
}
