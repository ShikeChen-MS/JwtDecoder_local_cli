using System.Runtime;
using System.Security.Cryptography;
using System.Text;
using JwtDecoder.Core;

namespace JwtDecoder;

internal static class Program
{
    /// Tokens read from --file or stdin are capped at this size to bound memory use.
    /// 1 MiB is far beyond any reasonable JWT (real-world tokens are typically < 10 KiB).
    private const int MaxTokenInputBytes = 1 * 1024 * 1024;

    public static int Main(string[] args)
    {
        int exitCode;
        try
        {
            exitCode = RunCore(args);
        }
        catch (Exception ex)
        {
            // Top-level safety net. Inner code maps known input/IO errors to exit 2 explicitly.
            Console.Error.WriteLine($"Unexpected error: {SanitizeMessage(ex.Message)}");
            exitCode = 1;
        }
        finally
        {
            // Aggressive scrubbing of any GC-reachable but now-dead allocations.
            // All sensitive buffers are explicitly zeroed before disposal; this forces those
            // dead buffers to be reclaimed and the heap compacted before the process exits.
            ForceAggressiveGc();
        }
        return exitCode;
    }

    private static int RunCore(string[] args)
    {
        var (opts, err) = Cli.Parse(args);
        if (err is not null)
        {
            Console.Error.WriteLine(err);
            Console.Error.WriteLine();
            Cli.PrintHelp(Console.Error);
            return 2;
        }

        if (opts!.Help)    { Cli.PrintHelp(Console.Out); return 0; }
        if (opts.Version)  { Console.Out.WriteLine($"jwtdecode {Cli.VersionString}"); return 0; }

        string? token;
        try
        {
            token = ReadToken(opts);
        }
        catch (FileNotFoundException ex)         { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
        catch (DirectoryNotFoundException ex)    { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
        catch (UnauthorizedAccessException ex)   { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
        catch (IOException ex)                   { Console.Error.WriteLine($"Error reading token: {SanitizeMessage(ex.Message)}"); return 2; }
        catch (InvalidDataException ex)          { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }

        if (string.IsNullOrWhiteSpace(token))
        {
            Console.Error.WriteLine("Error: no JWT provided. Pass a token, use --file <path>, or pipe one via stdin.");
            Console.Error.WriteLine();
            Cli.PrintHelp(Console.Error);
            return 2;
        }

        Jwt jwt;
        try { jwt = Jwt.Parse(token); }
        catch (FormatException ex) { Console.Error.WriteLine($"Invalid JWT: {ex.Message}"); return 2; }

        try
        {
            VerifyOutcome? verifyOutcome = null;
            KeyMaterial? key = null;
            if (opts.Verify)
            {
                // alg=none never has a key. Don't try to load one; go straight to Verify which
                // will return INVALID with a clear security warning.
                bool algIsNone = string.Equals(jwt.Algorithm, "none", StringComparison.OrdinalIgnoreCase);
                if (!algIsNone)
                {
                    try
                    {
                        if (opts.KeyFromStdin)
                            key = LoadKeyFromStdin(jwt.Algorithm);
                        else
                            key = KeyLoader.Load(opts.KeyFile!, jwt.Algorithm);
                    }
                    catch (FileNotFoundException ex)        { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
                    catch (DirectoryNotFoundException ex)   { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
                    catch (UnauthorizedAccessException ex)  { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
                    catch (IOException ex)                  { Console.Error.WriteLine($"Error reading key file: {SanitizeMessage(ex.Message)}"); return 2; }
                    catch (InvalidDataException ex)         { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
                    catch (NotSupportedException ex)        { Console.Error.WriteLine($"Error: {ex.Message}"); return 2; }
                }
            }

            try
            {
                if (opts.Verify) verifyOutcome = JwtVerifier.Verify(jwt, key);

                if (opts.Query is not null)
                {
                    // SECURITY: if the caller asked us to verify and verification failed, do NOT
                    // emit any query value on stdout. A downstream pipeline that ignores the exit
                    // code must not be able to consume claims from an unverified or invalid token
                    // (e.g. alg=none, wrong-key signature). The query value is suppressed; only a
                    // stderr diagnostic is written, and we return exit 3 just like the standard
                    // verify-failed path.
                    if (verifyOutcome is { Verified: false })
                    {
                        Console.Error.WriteLine(
                            "Error: signature verification failed; refusing to emit query output for an unverified token.");
                        if (!string.IsNullOrEmpty(verifyOutcome.Error))
                            Console.Error.WriteLine($"detail: {verifyOutcome.Error}");
                        return 3;
                    }

                    int notFoundIndex;
                    string missing;
                    try
                    {
                        notFoundIndex = Output.WriteQueryResults(Console.Out, jwt, opts.Query, opts.Raw, out missing);
                    }
                    catch (FormatException ex)
                    {
                        Console.Error.WriteLine($"Error: invalid query path: {ex.Message}");
                        return 2;
                    }
                    catch (InvalidDataException ex)
                    {
                        // Control-character refusal under --raw. Nothing was written to stdout.
                        Console.Error.WriteLine($"Error: {ex.Message}");
                        return 2;
                    }
                    if (notFoundIndex >= 0)
                    {
                        Console.Error.WriteLine($"Error: query path '{missing}' not found in token.");
                        return 2;
                    }
                    return 0;
                }

                if (opts.Detailed) Output.WriteDetailed(Console.Out, jwt, verifyOutcome);
                else               Output.WriteSimplified(Console.Out, jwt, verifyOutcome);

                return verifyOutcome is { Verified: false } ? 3 : 0;
            }
            finally
            {
                key?.Dispose();
            }
        }
        finally
        {
            jwt.Dispose();
        }
    }

    /// Reads the key material from stdin (when --key-file - is given), bounded to
    /// <see cref="KeyLoader.MaxKeyFileBytes"/>. The temporary read buffer is zeroed
    /// in <c>finally</c>; the bytes handed to <see cref="KeyLoader.LoadFromBytes"/>
    /// are owned by that call and zeroed there too.
    private static KeyMaterial LoadKeyFromStdin(string algorithm)
    {
        if (!Console.IsInputRedirected)
            throw new InvalidDataException(
                "'--key-file -' was specified but stdin is a terminal. " +
                "Pipe the key bytes into the process, or supply a path instead of '-'.");

        const int maxBytes = KeyLoader.MaxKeyFileBytes;
        byte[] buf = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        byte[] accumulator = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        int total = 0;
        try
        {
            using var stream = Console.OpenStandardInput();
            int n;
            while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            {
                if (total + n > maxBytes)
                    throw new InvalidDataException(
                        $"Key bytes on stdin exceed maximum size of {maxBytes:N0} bytes.");
                if (total + n > accumulator.Length)
                {
                    byte[] bigger = new byte[Math.Min(maxBytes + 1, accumulator.Length * 2)];
                    accumulator.AsSpan(0, total).CopyTo(bigger);
                    CryptographicOperations.ZeroMemory(accumulator);
                    accumulator = bigger;
                }
                buf.AsSpan(0, n).CopyTo(accumulator.AsSpan(total));
                total += n;
            }

            if (total == 0)
                throw new InvalidDataException("No key bytes were read from stdin.");

            return KeyLoader.LoadFromBytes(accumulator.AsSpan(0, total), algorithm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buf);
            CryptographicOperations.ZeroMemory(accumulator);
        }
    }

    /// Reads the token, bounded to <see cref="MaxTokenInputBytes"/>.
    /// Buffers used during read are explicitly zeroed even though the resulting <c>string</c>
    /// cannot be (strings are immutable in .NET).
    private static string? ReadToken(CliOptions opts)
    {
        if (opts.TokenFile is not null)
            return ReadAllTextBounded(opts.TokenFile, MaxTokenInputBytes, "token file");

        if (!string.IsNullOrEmpty(opts.Token))
            return opts.Token;

        if (Console.IsInputRedirected)
        {
            using var stream = Console.OpenStandardInput();
            return ReadStreamAsTextBounded(stream, MaxTokenInputBytes, "stdin");
        }

        return null;
    }

    private static string ReadAllTextBounded(string path, int maxBytes, string sourceName)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: false);

        long known = -1;
        try { known = fs.Length; } catch { /* not seekable */ }
        if (known > maxBytes)
            throw new InvalidDataException($"{sourceName} is too large ({known:N0} bytes; max {maxBytes:N0}).");

        return ReadStreamAsTextBounded(fs, maxBytes, sourceName);
    }

    private static string ReadStreamAsTextBounded(Stream stream, int maxBytes, string sourceName)
    {
        byte[] buf = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        byte[] accumulator = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        int total = 0;
        try
        {
            int n;
            while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            {
                if (total + n > maxBytes)
                {
                    throw new InvalidDataException($"{sourceName} exceeds maximum size of {maxBytes:N0} bytes.");
                }
                if (total + n > accumulator.Length)
                {
                    byte[] bigger = new byte[Math.Min(maxBytes + 1, accumulator.Length * 2)];
                    accumulator.AsSpan(0, total).CopyTo(bigger);
                    CryptographicOperations.ZeroMemory(accumulator);
                    accumulator = bigger;
                }
                buf.AsSpan(0, n).CopyTo(accumulator.AsSpan(total));
                total += n;
            }
            return Encoding.UTF8.GetString(accumulator, 0, total);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buf);
            CryptographicOperations.ZeroMemory(accumulator);
        }
    }

    /// Forces a maximally-aggressive compacting collection so any zeroed-but-still-reachable
    /// buffers held by JsonDocument/ArrayPool reclamation, plus our own dropped byte[] copies,
    /// are returned to the heap manager promptly.
    private static void ForceAggressiveGc()
    {
        try
        {
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        }
        catch
        {
            // Best-effort. Never let GC tuning break the exit path.
        }
    }

    /// Strip line breaks from error messages so they fit on one line and don't leak
    /// stack-trace fragments embedded in exception messages by some frameworks.
    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return string.Empty;
        return message.Replace('\r', ' ').Replace('\n', ' ');
    }
}
