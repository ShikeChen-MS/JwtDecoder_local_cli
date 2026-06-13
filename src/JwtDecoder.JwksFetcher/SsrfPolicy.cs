using System.Net;
using System.Net.Sockets;

namespace JwtDecoder.JwksFetcher;

/// <summary>
/// SSRF deny-list for URLs and resolved addresses. Applied per HTTPS hop.
/// </summary>
/// <remarks>
/// Two complementary checks live here:
/// <list type="bullet">
/// <item><see cref="AssertHostnameAllowed"/> — syntactic: rejects schemes
/// other than https, IP literals in private/loopback/link-local ranges, and
/// the hostname <c>localhost</c>. Cheap; runs before every request, including
/// when a proxy is in use.</item>
/// <item><see cref="IsForbiddenAddress"/> — semantic: tested against each
/// DNS-resolved <see cref="IPAddress"/>. Runs inside the
/// <c>SocketsHttpHandler.ConnectCallback</c> dial path so the actual TCP
/// connection target is what we vetted (defends against DNS rebinding).
/// Skipped when a proxy is configured because .NET delegates resolution to
/// the proxy in that case.</item>
/// </list>
/// </remarks>
internal static class SsrfPolicy
{
    /// <summary>Throws <see cref="InvalidDataException"/> if the URL is not safe to dispatch.</summary>
    public static void AssertHostnameAllowed(Uri uri, bool allowLoopbackForTesting = false)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Refusing non-HTTPS URL '{uri}': scheme must be 'https'.");

        string host = uri.Host;

        // Reject the literal hostname "localhost". We also reject other
        // commonly-used loopback aliases.
        if (!allowLoopbackForTesting && (
            string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(host, "ip6-localhost", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(host, "ip6-loopback", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException(
                $"Refusing URL '{uri}': hostname 'localhost' is on the SSRF deny-list.");
        }

        // If the host is an IP literal, validate it directly. (DNS rebinding
        // protection requires deferring to the address-level check after
        // resolution; that's IsForbiddenAddress, used in ConnectCallback.)
        if (IPAddress.TryParse(host, out var ip))
        {
            if (IsForbiddenAddress(ip, allowLoopbackForTesting))
                throw new InvalidDataException(
                    $"Refusing URL '{uri}': IP literal {ip} is on the SSRF deny-list.");
        }
    }

    /// <summary>Return true if the given resolved address must not be connected to.</summary>
    /// <param name="address">A resolved <see cref="IPAddress"/>.</param>
    /// <param name="allowLoopbackForTesting">
    /// When true, addresses in <c>127.0.0.0/8</c> and <c>::1</c> are permitted
    /// (test fixtures use this; CLI never sets it).
    /// </param>
    public static bool IsForbiddenAddress(IPAddress address, bool allowLoopbackForTesting = false)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Unmap IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1) so the IPv4 rules apply.
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] o = address.GetAddressBytes();

            // 127.0.0.0/8 — loopback
            if (o[0] == 127)
                return !allowLoopbackForTesting;

            // 10.0.0.0/8
            if (o[0] == 10) return true;
            // 172.16.0.0/12
            if (o[0] == 172 && (o[1] & 0xF0) == 16) return true;
            // 192.168.0.0/16
            if (o[0] == 192 && o[1] == 168) return true;
            // 169.254.0.0/16 — link-local (also covers AWS/GCP metadata 169.254.169.254)
            if (o[0] == 169 && o[1] == 254) return true;
            // 0.0.0.0/8 — "this network"
            if (o[0] == 0) return true;
            // 100.64.0.0/10 — carrier-grade NAT
            if (o[0] == 100 && (o[1] & 0xC0) == 64) return true;

            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(address))
                return !allowLoopbackForTesting;
            if (address.IsIPv6LinkLocal) return true;     // fe80::/10
            if (address.IsIPv6SiteLocal) return true;     // fec0::/10 (deprecated)
            if (address.IsIPv6Multicast) return true;
            byte[] o = address.GetAddressBytes();
            // fc00::/7 — Unique Local Addresses (ULA)
            if ((o[0] & 0xFE) == 0xFC) return true;
            // ::/128 — unspecified
            if (address.Equals(IPAddress.IPv6None)) return true;
            return false;
        }

        // Unknown address family — refuse out of caution.
        return true;
    }
}
