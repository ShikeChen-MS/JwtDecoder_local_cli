using JwtDecoder.JwksFetcher;

namespace JwksFetch;

/// <summary>
/// Parses <c>--header-file</c> contents into an immutable list of HTTP header
/// pairs, refusing any line that would smuggle dangerous semantics into the
/// request.
/// </summary>
/// <remarks>
/// Format: one <c>Name: value</c> per line. Empty lines and lines whose first
/// non-whitespace character is <c>#</c> are skipped (comment convention).
/// Names are RFC 7230 tokens; values may contain spaces but never CR/LF/NUL.
/// Dangerous header names (hop-by-hop / auth / routing) are refused — the
/// underlying <see cref="JwksClient"/> also refuses them, but the CLI catches
/// them earlier so the user gets a precise error message.
/// </remarks>
internal static class HeaderFileParser
{
    /// <summary>Maximum size of a <c>--header-file</c> input.</summary>
    public const int MaxHeaderFileBytes = 8 * 1024;

    /// <summary>Header names that must not be supplied via <c>--header-file</c>.</summary>
    private static readonly HashSet<string> Denylist = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Authorization", "Proxy-Authorization", "Cookie",
        "Connection", "TE", "Trailer", "Transfer-Encoding",
        "Upgrade", "Expect", "Content-Length",
    };

    /// <summary>Parse the file. Returns the list of headers in declared order.</summary>
    /// <exception cref="FileNotFoundException">Path does not exist.</exception>
    /// <exception cref="InvalidDataException">Format or denylist violation.</exception>
    public static IReadOnlyList<(string Name, string Value)> ParseFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new FileNotFoundException($"Header file not found: {path}", path);
        if (info.Length > MaxHeaderFileBytes)
            throw new InvalidDataException(
                $"Header file '{path}' is {info.Length:N0} bytes; max {MaxHeaderFileBytes:N0}.");

        string text = File.ReadAllText(path);
        return Parse(text);
    }

    /// <summary>Parse the contents (test-callable).</summary>
    public static IReadOnlyList<(string Name, string Value)> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new List<(string Name, string Value)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        int lineNo = 0;
        foreach (string rawLine in text.Split('\n'))
        {
            lineNo++;
            string line = rawLine.TrimEnd('\r');
            string trimmed = line.TrimStart();
            if (trimmed.Length == 0) continue;
            if (trimmed.StartsWith('#')) continue;

            int colon = line.IndexOf(':');
            if (colon <= 0)
                throw new InvalidDataException(
                    $"Header file line {lineNo}: missing ':' separator.");

            string name = line[..colon].Trim();
            string value = line[(colon + 1)..].TrimStart();

            if (name.Length == 0)
                throw new InvalidDataException(
                    $"Header file line {lineNo}: header name is empty.");
            if (!IsValidTokenName(name))
                throw new InvalidDataException(
                    $"Header file line {lineNo}: header name '{name}' contains characters outside RFC 7230 token charset.");
            if (Denylist.Contains(name))
                throw new InvalidDataException(
                    $"Header file line {lineNo}: header name '{name}' is on the denylist " +
                    "(hop-by-hop / auth / routing headers must not be supplied via --header-file).");
            if (ContainsForbiddenValueChar(value))
                throw new InvalidDataException(
                    $"Header file line {lineNo}: value contains CR, LF, or NUL.");
            if (!seen.Add(name))
                throw new InvalidDataException(
                    $"Header file line {lineNo}: duplicate header name '{name}' (case-insensitive).");

            result.Add((name, value));
        }
        return result;
    }

    private static bool IsValidTokenName(string s)
    {
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') continue;
            if (c >= 'a' && c <= 'z') continue;
            if (c >= '0' && c <= '9') continue;
            switch (c)
            {
                case '!': case '#': case '$': case '%': case '&':
                case '\'': case '*': case '+': case '-': case '.':
                case '^': case '_': case '`': case '|': case '~':
                    continue;
                default:
                    return false;
            }
        }
        return s.Length > 0;
    }

    private static bool ContainsForbiddenValueChar(string s)
    {
        foreach (char c in s)
        {
            if (c == '\r' || c == '\n' || c == '\0') return true;
        }
        return false;
    }
}
