using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JwksFetch.Tests;

/// <summary>
/// End-to-end tests of the jwksfetch CLI using <c>Program.RunCore</c> in-process,
/// driven against local <c>--jwks-file</c> inputs (no network — the network paths
/// are integration-tested at the library level in JwtDecoder.JwksFetcher.Tests).
/// </summary>
public class JwksFileEndToEndTests
{
    private static string MakeRsaJwksFile()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        string n = ToB64Url(p.Modulus!);
        string e = ToB64Url(p.Exponent!);
        string jwks = $"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"k1\",\"alg\":\"RS256\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
        string path = Path.Combine(Path.GetTempPath(), "jwks-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, jwks);
        return path;
    }

    private static string MakeTokenFile(string headerJson, string payloadJson)
    {
        string seg(string s) => ToB64Url(Encoding.UTF8.GetBytes(s));
        string token = $"{seg(headerJson)}.{seg(payloadJson)}.AAAA";
        string path = Path.Combine(Path.GetTempPath(), "tok-" + Guid.NewGuid().ToString("N") + ".jwt");
        File.WriteAllText(path, token);
        return path;
    }

    private static string ToB64Url(ReadOnlySpan<byte> bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        int trim = 0;
        while (trim < b64.Length && b64[b64.Length - 1 - trim] == '=') trim++;
        if (trim > 0) b64 = b64.Substring(0, b64.Length - trim);
        return b64.Replace('+', '-').Replace('/', '_');
    }

    [Fact]
    public void Help_returns_0()
    {
        var sw = new StringWriter();
        int code = Program.RunCore(new[] { "--help" }, sw, sw, null);
        Assert.Equal(0, code);
        Assert.Contains("jwksfetch", sw.ToString());
    }

    [Fact]
    public void Version_returns_0()
    {
        var sw = new StringWriter();
        int code = Program.RunCore(new[] { "--version" }, sw, sw, null);
        Assert.Equal(0, code);
        Assert.Contains("jwksfetch", sw.ToString());
    }

    [Fact]
    public void No_args_returns_2_with_help()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        int code = Program.RunCore(Array.Empty<string>(), stdout, stderr, null);
        Assert.Equal(2, code);
        Assert.Contains("--jwks-url", stderr.ToString());
    }

    [Fact]
    public void Unknown_option_returns_2()
    {
        var sw = new StringWriter();
        int code = Program.RunCore(new[] { "--bogus" }, sw, sw, null);
        Assert.Equal(2, code);
    }

    [Fact]
    public void JwksFile_RS256_happy_path_emits_one_pem_on_stdout()
    {
        string jwks = MakeRsaJwksFile();
        string tok = MakeTokenFile("{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}", "{\"sub\":\"x\"}");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", tok },
                stdout, stderr, null);
            Assert.Equal(0, code);
            string pem = stdout.ToString();
            Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
            Assert.Contains("-----END PUBLIC KEY-----", pem);
            // Confirm the emitted PEM round-trips through RSA.ImportFromPem.
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
        }
        finally { File.Delete(jwks); File.Delete(tok); }
    }

    [Fact]
    public void JwksFile_with_no_kid_match_returns_3()
    {
        string jwks = MakeRsaJwksFile();
        string tok = MakeTokenFile("{\"alg\":\"RS256\",\"kid\":\"WRONG\"}", "{}");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", tok },
                stdout, stderr, null);
            Assert.Equal(3, code);
        }
        finally { File.Delete(jwks); File.Delete(tok); }
    }

    [Fact]
    public void JwksFile_with_unsupported_alg_returns_3()
    {
        string jwks = MakeRsaJwksFile();
        string tok = MakeTokenFile("{\"alg\":\"HS256\"}", "{}");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", tok },
                stdout, stderr, null);
            Assert.Equal(3, code);
        }
        finally { File.Delete(jwks); File.Delete(tok); }
    }

    [Fact]
    public void JwksFile_with_malformed_token_returns_2()
    {
        string jwks = MakeRsaJwksFile();
        string tok = Path.Combine(Path.GetTempPath(), "tok-" + Guid.NewGuid().ToString("N") + ".jwt");
        File.WriteAllText(tok, "not.a.jwt.really.no");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", tok },
                stdout, stderr, null);
            Assert.Equal(2, code);
        }
        finally { File.Delete(jwks); File.Delete(tok); }
    }

    [Fact]
    public void JwksFile_with_missing_token_file_returns_2()
    {
        string jwks = MakeRsaJwksFile();
        try
        {
            var sw = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", "X:\\nope\\token.jwt" },
                sw, sw, null);
            Assert.Equal(2, code);
        }
        finally { File.Delete(jwks); }
    }

    [Fact]
    public void JwksFile_RefusesUrlOnly_argument_combo()
    {
        // --jwks-file with --bearer-token-file is rejected by argument parser.
        var sw = new StringWriter();
        int code = Program.RunCore(
            new[] { "--jwks-file", "k.json", "--token-file", "t.jwt", "--bearer-token-file", "b" },
            sw, sw, null);
        Assert.Equal(2, code);
    }

    [Fact]
    public void HttpJwksUrl_is_refused_at_runtime()
    {
        // The Uri parses, but JwksClient refuses non-HTTPS.
        string tok = MakeTokenFile("{\"alg\":\"RS256\",\"kid\":\"x\"}", "{}");
        try
        {
            var sw = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-url", "http://example.com/k", "--token-file", tok },
                sw, sw, null);
            Assert.True(code == 2 || code == 4, $"expected 2 or 4 for non-HTTPS, got {code}");
        }
        finally { File.Delete(tok); }
    }

    [Fact]
    public void Verbose_writes_jwt_sha256_to_stderr()
    {
        string jwks = MakeRsaJwksFile();
        string tok = MakeTokenFile("{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}", "{\"sub\":\"x\"}");
        try
        {
            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int code = Program.RunCore(
                new[] { "--jwks-file", jwks, "--token-file", tok, "--verbose" },
                stdout, stderr, null);
            Assert.Equal(0, code);
            Assert.Contains("jwt sha256:", stderr.ToString());
        }
        finally { File.Delete(jwks); File.Delete(tok); }
    }
}
