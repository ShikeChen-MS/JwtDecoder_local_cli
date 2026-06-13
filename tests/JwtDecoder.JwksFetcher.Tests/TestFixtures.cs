using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtDecoder.JwksFetcher.Tests;

/// <summary>
/// Helpers for building JWKS-shaped JSON fixtures and converting BCL keys
/// into JWK records in tests.
/// </summary>
internal static class TestFixtures
{
    /// <summary>Serialize a sequence of JWK property bags into a JWKS document.</summary>
    public static byte[] JwksOf(params IDictionary<string, object?>[] keys)
    {
        var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WritePropertyName("keys");
            w.WriteStartArray();
            foreach (var k in keys)
            {
                WriteJwk(w, k);
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    public static IDictionary<string, object?> RsaJwk(RSA rsa, string? kid = null, string? alg = "RS256")
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        var d = new Dictionary<string, object?>
        {
            ["kty"] = "RSA",
            ["n"] = Base64Url(p.Modulus!),
            ["e"] = Base64Url(p.Exponent!),
        };
        if (kid is not null) d["kid"] = kid;
        if (alg is not null) d["alg"] = alg;
        return d;
    }

    public static IDictionary<string, object?> EcJwk(ECDsa ec, string crv, string? kid = null, string? alg = null)
    {
        var p = ec.ExportParameters(includePrivateParameters: false);
        var d = new Dictionary<string, object?>
        {
            ["kty"] = "EC",
            ["crv"] = crv,
            ["x"] = Base64Url(p.Q.X!),
            ["y"] = Base64Url(p.Q.Y!),
        };
        if (kid is not null) d["kid"] = kid;
        if (alg is not null) d["alg"] = alg;
        return d;
    }

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static string Base64Url(ReadOnlySpan<byte> bytes)
    {
        // Mirrors JwtDecoder.JwksFetcher.Base64UrlCodec.Encode but lives here so
        // tests don't pierce internals beyond what they need to.
        string b64 = Convert.ToBase64String(bytes);
        int trim = 0;
        while (trim < b64.Length && b64[b64.Length - 1 - trim] == '=') trim++;
        if (trim > 0) b64 = b64.Substring(0, b64.Length - trim);
        return b64.Replace('+', '-').Replace('/', '_');
    }

    private static void WriteJwk(Utf8JsonWriter w, IDictionary<string, object?> jwk)
    {
        w.WriteStartObject();
        foreach (var kv in jwk)
        {
            switch (kv.Value)
            {
                case null:
                    w.WriteNull(kv.Key);
                    break;
                case string s:
                    w.WriteString(kv.Key, s);
                    break;
                case int n:
                    w.WriteNumber(kv.Key, n);
                    break;
                case bool b:
                    w.WriteBoolean(kv.Key, b);
                    break;
                case IEnumerable<string> arr:
                    w.WritePropertyName(kv.Key);
                    w.WriteStartArray();
                    foreach (var a in arr) w.WriteStringValue(a);
                    w.WriteEndArray();
                    break;
                default:
                    throw new InvalidOperationException(
                        $"TestFixtures.WriteJwk does not know how to serialize a value of type {kv.Value!.GetType()} for property '{kv.Key}'.");
            }
        }
        w.WriteEndObject();
    }
}
