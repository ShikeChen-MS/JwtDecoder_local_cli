using JwtDecoder.JwksFetcher;

namespace JwksFetch;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            return RunCore(args, Console.Out, Console.Error, Console.In);
        }
        catch (Exception ex)
        {
            // Last-resort net. Inner code maps known errors to exit 2/3/4 explicitly.
            Console.Error.WriteLine($"Unexpected error: {SanitizeMessage(ex.Message)}");
            return 1;
        }
        finally
        {
            ForceAggressiveGc();
        }
    }

    /// <summary>Run the CLI with explicit I/O. Returns the process exit code.</summary>
    /// <remarks>
    /// Exit codes:
    /// <list type="bullet">
    /// <item>0 — success, one PEM on stdout.</item>
    /// <item>1 — unexpected error (top-level safety net only).</item>
    /// <item>2 — invalid input (bad URL, bad option, missing file, refused scheme, oversized stdin).</item>
    /// <item>3 — logical refusal (no matching JWK, ambiguous kid, issuer mismatch, refused cross-host policy).</item>
    /// <item>4 — network error (timeout, TLS failure, oversized response, refused redirect, dangerous response header).</item>
    /// </list>
    /// </remarks>
    public static int RunCore(string[] args, TextWriter stdout, TextWriter stderr, TextReader? stdin)
    {
        var (opts, parseErr) = JwksFetch.Cli.Parse(args);
        if (parseErr is not null)
        {
            stderr.WriteLine(parseErr);
            stderr.WriteLine();
            JwksFetch.Cli.PrintHelp(stderr);
            return 2;
        }
        if (opts!.Help)    { JwksFetch.Cli.PrintHelp(stdout); return 0; }
        if (opts.Version)  { stdout.WriteLine($"jwksfetch {JwksFetch.Cli.VersionString}"); return 0; }

        // RunCore is sync; the network calls are sync-over-async at the boundary.
        // Using GetAwaiter().GetResult() is acceptable in a single-shot CLI.
        try
        {
            return RunAsync(opts, stdout, stderr).GetAwaiter().GetResult();
        }
        catch (AggregateException ex) when (ex.InnerException is not null)
        {
            return HandleException(ex.InnerException, stderr);
        }
        catch (Exception ex)
        {
            return HandleException(ex, stderr);
        }
    }

    private static async Task<int> RunAsync(JwksFetchOptions opts, TextWriter stdout, TextWriter stderr)
    {
        // 1. Read the JWT (file or stdin) using the SAME parser that jwtdecode uses
        //    (Jwt.Parse) — no second parser, no parser-differential between binaries.
        byte[] tokenBytes;
        try
        {
            tokenBytes = ReadTokenBytes(opts);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException
                                      or UnauthorizedAccessException or IOException
                                      or InvalidDataException)
        {
            stderr.WriteLine($"Error: {SanitizeMessage(ex.Message)}");
            return 2;
        }

        if (opts.Verbose) WriteJwtIdentityHash(stderr, tokenBytes);

        string jwtAlg;
        string? jwtKid;
        try
        {
            (jwtAlg, jwtKid) = ParseTokenAlgKid(tokenBytes);
        }
        catch (FormatException ex)
        {
            stderr.WriteLine($"Error: invalid JWT: {ex.Message}");
            return 2;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(tokenBytes);
        }

        // 2. Build FetcherOptions from CLI flags.
        FetcherOptions fopts;
        try
        {
            fopts = BuildFetcherOptions(opts, stderr);
        }
        catch (InvalidDataException ex)
        {
            stderr.WriteLine($"Error: {ex.Message}");
            return 2;
        }

        if (opts.Verbose) WriteVerboseProxyLine(stderr, opts);

        // 3. Acquire the JWKS bytes (one of three sources).
        byte[] jwksBytes;
        bool crossHostJwksUri = false;

        try
        {
            if (opts.JwksFile is not null)
            {
                if (opts.Verbose) stderr.WriteLine($"reading jwks file: {opts.JwksFile}");
                jwksBytes = ReadFileBounded(opts.JwksFile, JwksDocument.MaxJwksBytes, "JWKS file");
            }
            else if (opts.JwksUrl is not null)
            {
                if (opts.Verbose) stderr.WriteLine($"fetching jwks: {opts.JwksUrl}");
                var r = await JwtDecoder.JwksFetcher.JwksClient.FetchAsync(opts.JwksUrl, fopts);
                jwksBytes = r.Body;
            }
            else // FromIssuer
            {
                if (opts.Verbose) stderr.WriteLine($"discovering issuer: {opts.FromIssuer}");
                // Pass RequireSameHostJwksUri into the library so the
                // cross-host policy is enforced BEFORE the JWKS fetch. If
                // we deferred to a post-fetch check here, the bearer token
                // (when supplied) would already have leaked to the
                // cross-host endpoint. (Final-review B2.)
                var discoveryOpts = new JwtDecoder.JwksFetcher.OidcDiscoveryOptions
                {
                    RequireSameHostJwksUri = opts.RequireSameHostJwksUri,
                };
                var r = await JwtDecoder.JwksFetcher.OidcDiscoveryClient
                    .DiscoverAndFetchJwksAsync(opts.FromIssuer!, fopts, discoveryOpts);
                jwksBytes = r.JwksDocument;
                crossHostJwksUri = r.CrossHostJwksUri;

                if (crossHostJwksUri)
                {
                    stderr.WriteLine(
                        $"warning: jwks_uri host '{r.JwksUri.Host}' differs from issuer host '{opts.FromIssuer!.Host}' " +
                        "(allowed; pass --require-same-host-jwks-uri to refuse).");
                }
                if (opts.Verbose) stderr.WriteLine($"jwks fetched from: {r.JwksUri}");
            }
        }
        catch (InvalidDataException ex)
        {
            return MapDataExceptionToExit(ex, stderr);
        }
        catch (System.Net.Http.HttpRequestException ex)
        {
            stderr.WriteLine($"Network error: {FormatExceptionChain(ex)}");
            return 4;
        }
        catch (TaskCanceledException)
        {
            stderr.WriteLine("Network error: request timed out.");
            return 4;
        }
        finally
        {
            // Bearer-token byte[] is owned by us (CLI created it from the file).
            // Zero on every exit path — including the early returns above — so
            // that the secret bytes don't outlive the network request that
            // needed them. The HTTP-layer string copy is unavoidable and is
            // documented on FetcherOptions.BearerTokenBytes (round-6 #1).
            if (fopts.BearerTokenBytes is { Length: > 0 })
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(fopts.BearerTokenBytes);
        }

        // 4. Parse + select + emit PEM.
        try
        {
            var keys = JwksDocument.Parse(jwksBytes);
            var selection = JwkSelector.Select(keys, jwtAlg, jwtKid);
            if (selection.Warning is not null)
                stderr.WriteLine($"warning: {selection.Warning}");
            if (opts.Verbose)
                stderr.WriteLine($"selected key: kid={selection.Selected.Kid ?? "(none)"}, kty={selection.Selected.Kty}, alg={selection.Selected.Alg ?? "(inferred)"}");

            string pem = JwkToPem.ToPublicKeyPem(selection.Selected);
            stdout.Write(pem);
            if (!pem.EndsWith('\n')) stdout.WriteLine();
            return 0;
        }
        catch (InvalidDataException ex)
        {
            return MapDataExceptionToExit(ex, stderr);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(jwksBytes);
        }
    }

    private static int MapDataExceptionToExit(InvalidDataException ex, TextWriter stderr)
    {
        // Distinguish "logical refusal" (no match / ambiguous / issuer mismatch / refused type)
        // from "invalid input" (bad URL, malformed JWKS, etc.). Best-effort substring routing —
        // exit 3 reserved for issues the user can address by changing JWKS content / issuer URL.
        string m = ex.Message;
        bool isLogicalRefusal =
            m.Contains("issuer mismatch", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("No JWK", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("ambiguous", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("Multiple", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("cross-host", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("not supported by JWKS-based selection", StringComparison.OrdinalIgnoreCase);

        // Network-layer refusals (SSRF, oversized body, redirect cap, etc.) map to 4.
        bool isNetworkRefusal =
            m.Contains("SSRF", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("redirect", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("maximum size", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("exceeds maximum", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("non-HTTPS", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("Refusing URL", StringComparison.OrdinalIgnoreCase);

        stderr.WriteLine($"Error: {SanitizeMessage(m)}");
        if (isLogicalRefusal) return 3;
        if (isNetworkRefusal) return 4;
        return 2;
    }

    private static int HandleException(Exception ex, TextWriter stderr)
    {
        if (ex is System.Net.Http.HttpRequestException or TaskCanceledException
              or System.Security.Authentication.AuthenticationException
              or System.Net.Sockets.SocketException)
        {
            stderr.WriteLine($"Network error: {FormatExceptionChain(ex)}");
            return 4;
        }
        if (ex is InvalidDataException ide) return MapDataExceptionToExit(ide, stderr);
        if (ex is FormatException or NotSupportedException or ArgumentException
                                  or FileNotFoundException or DirectoryNotFoundException
                                  or UnauthorizedAccessException or IOException)
        {
            stderr.WriteLine($"Error: {SanitizeMessage(ex.Message)}");
            return 2;
        }
        stderr.WriteLine($"Unexpected error: {FormatExceptionChain(ex)}");
        return 1;
    }

    /// <summary>
    /// Surface the inner-exception chain so callers see WHY a network call
    /// failed, not just "see inner exception". The outer
    /// HttpRequestException message is often "The SSL connection could not
    /// be established, see inner exception." — the inner usually carries
    /// the actual cause (cert chain failure, name mismatch, socket reset,
    /// etc.). Inner messages are CR/LF/NUL-sanitised and capped to a
    /// reasonable depth to keep output predictable.
    /// </summary>
    private static string FormatExceptionChain(Exception ex)
    {
        const int maxDepth = 5;
        var parts = new System.Text.StringBuilder();
        parts.Append(SanitizeMessage(ex.Message));
        var inner = ex.InnerException;
        int depth = 0;
        while (inner is not null && depth < maxDepth)
        {
            parts.Append(" -> ");
            parts.Append(inner.GetType().Name);
            parts.Append(": ");
            parts.Append(SanitizeMessage(inner.Message));
            inner = inner.InnerException;
            depth++;
        }
        return parts.ToString();
    }

    private static byte[] ReadTokenBytes(JwksFetchOptions opts)
    {
        if (opts.TokenFile is not null)
            return ReadFileBounded(opts.TokenFile, JwtDecoder.Core.Jwt.MaxTokenChars, "token file");

        if (!Console.IsInputRedirected)
            throw new InvalidDataException(
                "No --token-file given and stdin is a terminal. " +
                "Pipe the JWT into the process or supply --token-file <path>.");

        using var s = Console.OpenStandardInput();
        return ReadStreamBounded(s, JwtDecoder.Core.Jwt.MaxTokenChars, "stdin token");
    }

    private static byte[] ReadFileBounded(string path, int maxBytes, string sourceName)
        // Round-5 I1: delegate to the shared streaming bounded reader so the
        // CLI, the PowerShell cmdlet, and the JwksFetcher library all use one
        // TOCTOU-safe implementation. (Previously this site combined
        // FileInfo.Length with File.ReadAllBytes, which could be raced by a
        // growing file.)
        => JwtDecoder.JwksFetcher.BoundedFileReader.ReadAllBytes(path, maxBytes, sourceName);

    private static byte[] ReadStreamBounded(Stream stream, int maxBytes, string sourceName)
    {
        var ms = new MemoryStream();
        byte[] buf = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        int total = 0;
        try
        {
            int n;
            while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            {
                if (total + n > maxBytes)
                    throw new InvalidDataException($"{sourceName} exceeds maximum size of {maxBytes:N0} bytes.");
                ms.Write(buf, 0, n);
                total += n;
            }
            return ms.ToArray();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buf);
        }
    }

    /// <summary>Use Core's hardened parser to extract kid/alg. No second JWT parser.</summary>
    private static (string Alg, string? Kid) ParseTokenAlgKid(byte[] tokenBytes)
    {
        string s = System.Text.Encoding.UTF8.GetString(tokenBytes).Trim();
        using var jwt = JwtDecoder.Core.Jwt.Parse(s);
        string alg = jwt.Algorithm;
        string? kid = null;
        if (jwt.Header.RootElement.TryGetProperty("kid", out var kidEl) &&
            kidEl.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            kid = kidEl.GetString();
        }
        return (alg, kid);
    }

    private static FetcherOptions BuildFetcherOptions(JwksFetchOptions opts, TextWriter stderr)
    {
        byte[]? bearerBytes = null;
        if (opts.BearerTokenFile is not null)
        {
            bearerBytes = ReadFileBounded(opts.BearerTokenFile, 16 * 1024, "bearer-token file");
            // Strip a single trailing newline so people can `echo $TOK > f` safely.
            int len = bearerBytes.Length;
            if (len >= 2 && bearerBytes[len - 2] == (byte)'\r' && bearerBytes[len - 1] == (byte)'\n') len -= 2;
            else if (len >= 1 && bearerBytes[len - 1] == (byte)'\n') len -= 1;
            if (len != bearerBytes.Length)
            {
                byte[] trimmed = new byte[len];
                bearerBytes.AsSpan(0, len).CopyTo(trimmed);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bearerBytes);
                bearerBytes = trimmed;
            }
            // Reject CR/LF inside the bearer token.
            foreach (byte b in bearerBytes)
                if (b == (byte)'\r' || b == (byte)'\n' || b == 0)
                    throw new InvalidDataException("bearer-token file contains CR, LF, or NUL inside the token body.");
        }

        IReadOnlyList<(string Name, string Value)>? extra = null;
        if (opts.HeaderFile is not null)
            extra = JwtDecoder.JwksFetcher.HeaderFileParser.ParseFile(opts.HeaderFile);

        return new FetcherOptions
        {
            Timeout = TimeSpan.FromSeconds(opts.TimeoutSeconds),
            MaxResponseBytes = opts.MaxResponseBytes,
            MaxRedirects = opts.MaxRedirects,
            CaBundlePath = opts.CaBundle,
            BearerTokenBytes = bearerBytes,
            ExtraHeaders = extra,
            ProxyMode = opts.ProxyMode,
            ProxyUri = opts.ProxyUri,
            ProxyDefaultCredentials = opts.ProxyDefaultCredentials,
            AllowPrivateProxy = opts.AllowPrivateProxy,
            SendBearerToDiscovery = opts.BearerTokenDiscovery,
#if JWKSFETCH_TEST_HOOKS
            AllowLoopbackForTesting = TestHooks.AllowLoopbackForTesting,
#else
            // No test hook in the production build — SSRF policy always
            // refuses loopback. The symbol JWKSFETCH_TEST_HOOKS is defined
            // by JwksFetch.Tests.csproj only (final-review I6).
            AllowLoopbackForTesting = false,
#endif
        };
    }

    private static void WriteJwtIdentityHash(TextWriter stderr, byte[] tokenBytes)
    {
        // Round-2 review item: print SHA-256 of the JWT bytes so the operator can
        // confirm both binaries (jwksfetch + jwtdecode) saw the same token.
        using var sha = System.Security.Cryptography.SHA256.Create();
        byte[] hash = sha.ComputeHash(tokenBytes);
        stderr.WriteLine($"jwt sha256: {Convert.ToHexStringLower(hash)}");
    }

    private static void WriteVerboseProxyLine(TextWriter stderr, JwksFetchOptions opts)
    {
        switch (opts.ProxyMode)
        {
            case ProxyMode.None: stderr.WriteLine("proxy: none"); break;
            case ProxyMode.Explicit: stderr.WriteLine($"proxy: explicit {opts.ProxyUri}"); break;
            case ProxyMode.System:
                stderr.WriteLine($"proxy: system (HTTPS_PROXY={Environment.GetEnvironmentVariable("HTTPS_PROXY") ?? "(unset)"})");
                break;
        }
    }

    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return string.Empty;
        return message.Replace('\r', ' ').Replace('\n', ' ');
    }

    private static void ForceAggressiveGc()
    {
        try
        {
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
                System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        }
        catch { /* Best effort. */ }
    }
}

