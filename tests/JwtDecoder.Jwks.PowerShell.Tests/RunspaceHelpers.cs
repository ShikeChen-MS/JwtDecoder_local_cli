using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography;
using System.Text;

namespace JwtDecoder.Jwks.PowerShell.Tests;

/// <summary>
/// Shared helpers for tests that drive cmdlets through an in-process PowerShell
/// runspace. The runspace is created per test (cheap) so cross-test state can't leak.
/// </summary>
internal static class RunspaceHelpers
{
    /// <summary>Create a runspace with both Jwks and offline JwtDecoder cmdlets registered.</summary>
    public static (Runspace runspace, System.Management.Automation.PowerShell powershell) CreateLoaded()
    {
        var iss = InitialSessionState.CreateDefault();
        iss.ImportPSModule(new[]
        {
            typeof(GetJsonWebKeyCommand).Assembly.Location,
            typeof(JwtDecoder.PowerShell.TestJsonWebTokenSignatureCommand).Assembly.Location,
        });
        var rs = RunspaceFactory.CreateRunspace(iss);
        rs.Open();
        var ps = System.Management.Automation.PowerShell.Create();
        ps.Runspace = rs;
        return (rs, ps);
    }

    public static string MakeRsaJwksFile(out string kid)
    {
        kid = "ut-rsa-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        string n = B64Url(p.Modulus!);
        string e = B64Url(p.Exponent!);
        string jwks = $"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"{kid}\",\"alg\":\"RS256\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
        string path = Path.Combine(Path.GetTempPath(), "jwks-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, jwks);
        return path;
    }

    /// <summary>Make a real signed RS256 JWT plus the matching RSA-bearing JWKS file.</summary>
    public static (string Token, string JwksPath, string Kid) MakeSignedRsaPair()
    {
        string kid = "ut-rsa-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        using var rsa = RSA.Create(2048);
        var pPub = rsa.ExportParameters(false);

        string headerJson  = $"{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}";
        string payloadJson = $"{{\"sub\":\"alice\",\"iat\":1700000000}}";
        string h = B64Url(Encoding.UTF8.GetBytes(headerJson));
        string p = B64Url(Encoding.UTF8.GetBytes(payloadJson));
        byte[] signingInput = Encoding.ASCII.GetBytes(h + "." + p);
        byte[] sig = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        string token = $"{h}.{p}.{B64Url(sig)}";

        string n = B64Url(pPub.Modulus!);
        string e = B64Url(pPub.Exponent!);
        string jwks = $"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"{kid}\",\"alg\":\"RS256\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
        string jwksPath = Path.Combine(Path.GetTempPath(), "jwks-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(jwksPath, jwks);
        return (token, jwksPath, kid);
    }

    public static string MakeUnsignedToken(string headerJson, string payloadJson)
    {
        string h = B64Url(Encoding.UTF8.GetBytes(headerJson));
        string p = B64Url(Encoding.UTF8.GetBytes(payloadJson));
        return $"{h}.{p}.AAAA";
    }

    public static string B64Url(ReadOnlySpan<byte> bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        int trim = 0;
        while (trim < b64.Length && b64[b64.Length - 1 - trim] == '=') trim++;
        if (trim > 0) b64 = b64.Substring(0, b64.Length - trim);
        return b64.Replace('+', '-').Replace('/', '_');
    }
}
