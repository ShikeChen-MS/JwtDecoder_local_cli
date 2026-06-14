using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using JwtDecoder.Core;
using JwtDecoder.JwksFetcher;

namespace JwtDecoder.Jwks.PowerShell;

/// <summary>
/// <c>Get-JsonWebKey</c> — acquire a single public verification key for a JWT
/// from a JWKS endpoint (or via OIDC discovery, or from a local JWKS file).
/// </summary>
/// <remarks>
/// Three parameter sets carry the key source: <c>JwksUri</c>, <c>Issuer</c>
/// (OIDC discovery), and <c>JwksFile</c>. The JWT is supplied via <c>-Token</c>
/// (literal string) or <c>-Path</c> (file). Output is a typed
/// <see cref="JsonWebKey"/> whose <c>PublicKey</c> property feeds directly into
/// the offline module's <c>Test-JsonWebTokenSignature -PublicKey</c> by value
/// or by pipeline property name.
/// </remarks>
[Cmdlet(VerbsCommon.Get, "JsonWebKey", DefaultParameterSetName = ParamSetJwksFile)]
[OutputType(typeof(JsonWebKey))]
public sealed class GetJsonWebKeyCommand : PSCmdlet
{
    private const string ParamSetJwksUri  = "JwksUri";
    private const string ParamSetIssuer   = "Issuer";
    private const string ParamSetJwksFile = "JwksFile";

    // ----- Key source (exactly one). -----
    [Parameter(Mandatory = true, ParameterSetName = ParamSetJwksUri)]
    public Uri? JwksUri { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = ParamSetIssuer)]
    public Uri? Issuer { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = ParamSetJwksFile)]
    [Alias("JwksPath")]
    public string JwksFile { get; set; } = string.Empty;

    // ----- Token source. Token wins when both are given (-Token is positional). -----
    [Parameter(Position = 0)]
    public string? Token { get; set; }

    [Parameter]
    public string? Path { get; set; }

    // ----- Network knobs. -----
    [Parameter] public string? BearerTokenFile { get; set; }
    [Parameter] public SwitchParameter BearerTokenDiscovery { get; set; }
    [Parameter] public string? HeaderFile { get; set; }
    [Parameter] public string? CaBundle { get; set; }
    [Parameter] public int? TimeoutSeconds { get; set; }
    [Parameter] public int? MaxResponseBytes { get; set; }
    [Parameter] public int? MaxRedirects { get; set; }

    [Parameter(ParameterSetName = ParamSetIssuer)]
    public SwitchParameter RequireSameHostJwksUri { get; set; }

    // ----- Proxy. -----
    [Parameter] public Uri? Proxy { get; set; }
    [Parameter] public SwitchParameter UseSystemProxy { get; set; }
    [Parameter] public SwitchParameter ProxyDefaultCredentials { get; set; }
    [Parameter] public SwitchParameter AllowPrivateProxy { get; set; }

    protected override void ProcessRecord()
    {
        // --- 1. Read token. ---
        byte[]? tokenBytes;
        try { tokenBytes = ReadTokenBytes(); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException
                                      or UnauthorizedAccessException or IOException
                                      or InvalidDataException or ArgumentException)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "TokenReadFailed",
                ErrorCategory.InvalidArgument, null));
            return;
        }

        string jwtAlg;
        string? jwtKid;
        try
        {
            string token = Encoding.UTF8.GetString(tokenBytes).Trim();
            using var jwt = Jwt.Parse(token);
            jwtAlg = jwt.Algorithm;
            jwtKid = null;
            if (jwt.Header.RootElement.TryGetProperty("kid", out var kEl) &&
                kEl.ValueKind == System.Text.Json.JsonValueKind.String)
                jwtKid = kEl.GetString();
        }
        catch (FormatException ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "InvalidJwt",
                ErrorCategory.InvalidData, null));
            return;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
        }

        // --- 2. Build FetcherOptions from CLI knobs. ---
        FetcherOptions fopts;
        try { fopts = BuildFetcherOptions(); }
        catch (Exception ex) when (ex is FileNotFoundException or InvalidDataException
                                       or ArgumentException)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "BadOptions",
                ErrorCategory.InvalidArgument, null));
            return;
        }

        // --- 3. Acquire JWKS bytes. ---
        byte[] jwksBytes;
        Uri? sourceUri = null;
        try
        {
            switch (ParameterSetName)
            {
                case ParamSetJwksFile:
                    {
                        string resolved = GetUnresolvedProviderPathFromPSPath(JwksFile);
                        jwksBytes = ReadFileBounded(resolved, JwksDocument.MaxJwksBytes, "JWKS file");
                        sourceUri = null;
                        break;
                    }
                case ParamSetJwksUri:
                    {
                        var r = JwksClient.FetchAsync(JwksUri!, fopts).GetAwaiter().GetResult();
                        jwksBytes = r.Body;
                        sourceUri = r.FinalUri;
                        break;
                    }
                case ParamSetIssuer:
                    {
                        var discoveryOpts = new OidcDiscoveryOptions
                        {
                            RequireSameHostJwksUri = RequireSameHostJwksUri.IsPresent,
                        };
                        var r = OidcDiscoveryClient.DiscoverAndFetchJwksAsync(Issuer!, fopts, discoveryOpts)
                            .GetAwaiter().GetResult();
                        jwksBytes = r.JwksDocument;
                        sourceUri = r.JwksUri;
                        if (r.CrossHostJwksUri)
                        {
                            WriteWarning(
                                $"jwks_uri host '{r.JwksUri.Host}' differs from issuer host '{Issuer!.Host}'.");
                        }
                        break;
                    }
                default:
                    ThrowTerminatingError(new ErrorRecord(
                        new InvalidOperationException($"Unknown parameter set: {ParameterSetName}"),
                        "UnknownParamSet", ErrorCategory.InvalidOperation, null));
                    return;
            }
        }
        catch (System.Net.Http.HttpRequestException ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "JwksFetchFailed",
                ErrorCategory.ConnectionError, JwksUri ?? Issuer));
            return;
        }
        catch (TaskCanceledException ex)
        {
            ThrowTerminatingError(new ErrorRecord(
                new TimeoutException("JWKS fetch timed out.", ex), "JwksFetchTimeout",
                ErrorCategory.OperationTimeout, JwksUri ?? Issuer));
            return;
        }
        catch (InvalidDataException ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "JwksRejected",
                ErrorCategory.InvalidData, JwksUri ?? Issuer));
            return;
        }

        // --- 4. Parse, select, build the typed AsymmetricAlgorithm, emit. ---
        try
        {
            var keys = JwksDocument.Parse(jwksBytes);
            var sel = JwkSelector.Select(keys, jwtAlg, jwtKid);
            if (sel.Warning is not null) WriteWarning(sel.Warning);

            string pem = JwkToPem.ToPublicKeyPem(sel.Selected);
            AsymmetricAlgorithm key = sel.Selected.Kty switch
            {
                "RSA" => CreateRsaFromPem(pem),
                "EC"  => CreateEcFromPem(pem),
                _ => throw new InvalidDataException(
                    $"Internal: JwkToPem produced an unsupported key type '{sel.Selected.Kty}'."),
            };

            var jwk = JsonWebKey.CreateOwned(
                pem: pem,
                algorithm: sel.Selected.Alg ?? jwtAlg,
                kty: sel.Selected.Kty,
                kid: sel.Selected.Kid,
                crv: sel.Selected.Crv,
                sourceUri: sourceUri,
                publicKey: key);
            WriteObject(jwk);
        }
        catch (InvalidDataException ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "JwkSelectionFailed",
                ErrorCategory.InvalidData, null));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(jwksBytes);
        }
    }

    private byte[] ReadTokenBytes()
    {
        if (Token is not null && Path is not null)
            throw new ArgumentException("Specify -Token OR -Path, not both.");
        if (Token is null && Path is null)
            throw new ArgumentException("One of -Token or -Path is required.");

        if (Token is not null)
            return Encoding.UTF8.GetBytes(Token);

        string resolved = GetUnresolvedProviderPathFromPSPath(Path!);
        return ReadFileBounded(resolved, Jwt.MaxTokenChars, "token file");
    }

    /// <summary>
    /// Read a file as bytes but refuse anything over <paramref name="maxBytes"/>,
    /// using a streaming reader so a file growing between size-check and read
    /// can't slip past the cap. Matches the CLI's bounded-read semantics so
    /// huge local files can't cause a managed OOM before the parser's own
    /// size caps trigger (final-review I8 / F5).
    /// </summary>
    private static byte[] ReadFileBounded(string path, int maxBytes, string sourceName)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"{sourceName} not found: {path}", path);

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: false);

        // Read into a single buffer sized to maxBytes + 1 so we can tell
        // "size cap exceeded" from "file is exactly maxBytes". The +1 byte
        // is never returned.
        byte[] buf = new byte[maxBytes + 1];
        int total = 0;
        int n;
        while ((n = fs.Read(buf, total, buf.Length - total)) > 0)
        {
            total += n;
            if (total > maxBytes)
                throw new InvalidDataException(
                    $"{sourceName} '{path}' exceeds maximum of {maxBytes:N0} bytes.");
        }
        byte[] exact = new byte[total];
        Buffer.BlockCopy(buf, 0, exact, 0, total);
        return exact;
    }

    private FetcherOptions BuildFetcherOptions()
    {
        // Proxy mode resolution.
        var pmode = ProxyMode.None;
        if (Proxy is not null && UseSystemProxy.IsPresent)
            throw new ArgumentException("-Proxy and -UseSystemProxy are mutually exclusive.");
        if (Proxy is not null) pmode = ProxyMode.Explicit;
        else if (UseSystemProxy.IsPresent) pmode = ProxyMode.System;

        if (pmode == ProxyMode.None && ProxyDefaultCredentials.IsPresent)
            throw new ArgumentException("-ProxyDefaultCredentials requires -Proxy or -UseSystemProxy.");
        if (pmode == ProxyMode.None && AllowPrivateProxy.IsPresent)
            throw new ArgumentException("-AllowPrivateProxy requires -Proxy or -UseSystemProxy.");

        // Bearer token bytes (raw, never a string).
        byte[]? bearer = null;
        if (BearerTokenFile is not null)
        {
            string resolved = GetUnresolvedProviderPathFromPSPath(BearerTokenFile);
            var info = new FileInfo(resolved);
            if (!info.Exists)
                throw new FileNotFoundException($"Bearer-token file not found: {resolved}", resolved);
            if (info.Length > 16 * 1024)
                throw new InvalidDataException($"Bearer-token file too large: {info.Length} bytes (max 16384).");
            bearer = File.ReadAllBytes(resolved);
            int len = bearer.Length;
            if (len >= 2 && bearer[len - 2] == (byte)'\r' && bearer[len - 1] == (byte)'\n') len -= 2;
            else if (len >= 1 && bearer[len - 1] == (byte)'\n') len -= 1;
            if (len != bearer.Length)
            {
                byte[] trimmed = new byte[len];
                bearer.AsSpan(0, len).CopyTo(trimmed);
                CryptographicOperations.ZeroMemory(bearer);
                bearer = trimmed;
            }
            foreach (byte b in bearer)
                if (b == (byte)'\r' || b == (byte)'\n' || b == 0)
                    throw new InvalidDataException("Bearer-token file body contains CR, LF, or NUL.");
        }

        if (BearerTokenDiscovery.IsPresent && bearer is null)
            throw new ArgumentException("-BearerTokenDiscovery requires -BearerTokenFile.");

        // Extra headers via the same parser the CLI uses.
        IReadOnlyList<(string Name, string Value)>? extra = null;
        if (HeaderFile is not null)
        {
            string resolved = GetUnresolvedProviderPathFromPSPath(HeaderFile);
            extra = JwtDecoder.JwksFetcher.HeaderFileParser.ParseFile(resolved);
        }

        string? caBundle = CaBundle is null ? null : GetUnresolvedProviderPathFromPSPath(CaBundle);

        return new FetcherOptions
        {
            Timeout = TimeoutSeconds.HasValue
                ? TimeSpan.FromSeconds(Math.Clamp(TimeoutSeconds.Value, 1, 60))
                : TimeSpan.FromSeconds(10),
            MaxResponseBytes = MaxResponseBytes ?? (256 * 1024),
            MaxRedirects = MaxRedirects ?? 3,
            CaBundlePath = caBundle,
            BearerTokenBytes = bearer,
            ExtraHeaders = extra,
            ProxyMode = pmode,
            ProxyUri = Proxy,
            ProxyDefaultCredentials = ProxyDefaultCredentials.IsPresent,
            AllowPrivateProxy = AllowPrivateProxy.IsPresent,
            SendBearerToDiscovery = BearerTokenDiscovery.IsPresent,
        };
    }

    private static RSA CreateRsaFromPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    private static ECDsa CreateEcFromPem(string pem)
    {
        var ec = ECDsa.Create();
        ec.ImportFromPem(pem);
        return ec;
    }
}
