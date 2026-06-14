namespace JwtDecoder.JwksFetcher;

/// <summary>
/// Streaming, size‑capped file reader.
/// </summary>
/// <remarks>
/// All file inputs in jwksfetch / the Jwks PowerShell cmdlet must cap the
/// amount of data they pull off disk so a giant or growing local file can't
/// blow the process out of memory before the parser's own checks fire.
/// <para>
/// Implemented as a streaming read with a hard cap of <c>maxBytes + 1</c>
/// instead of <c>FileInfo.Length</c> + <c>File.ReadAllBytes</c>. The two-call
/// pattern is TOCTOU: a file growing between the size check and the read can
/// slip past. The streaming read aborts the moment the cap is exceeded,
/// regardless of how the file grew. (Final-review round-5 I1.)
/// </para>
/// </remarks>
public static class BoundedFileReader
{
    /// <summary>Read <paramref name="path"/> into a byte array, refusing anything past <paramref name="maxBytes"/>.</summary>
    /// <exception cref="ArgumentNullException">If <paramref name="path"/> is null.</exception>
    /// <exception cref="FileNotFoundException">If the file does not exist.</exception>
    /// <exception cref="InvalidDataException">If the file is larger than <paramref name="maxBytes"/>.</exception>
    public static byte[] ReadAllBytes(string path, int maxBytes, string sourceName)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!File.Exists(path))
            throw new FileNotFoundException($"{sourceName} not found: {path}", path);
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes), "maxBytes must be positive.");

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: false);

        // Output buffer sized to maxBytes + 1 so we can detect "exceeded
        // the cap" deterministically: if the file is exactly maxBytes we
        // succeed; one more byte and Read returns nonzero past the cap.
        byte[] buf = new byte[maxBytes + 1];
        int total = 0;
        int n;
        while (total < buf.Length && (n = fs.Read(buf, total, buf.Length - total)) > 0)
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

    /// <summary>Read <paramref name="path"/> as UTF-8 text, refusing anything past <paramref name="maxBytes"/>.</summary>
    public static string ReadAllText(string path, int maxBytes, string sourceName)
    {
        byte[] bytes = ReadAllBytes(path, maxBytes, sourceName);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
