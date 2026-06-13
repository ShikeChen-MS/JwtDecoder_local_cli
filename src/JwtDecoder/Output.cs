using System.Globalization;
using System.Text;
using System.Text.Json;
using JwtDecoder.Core;

namespace JwtDecoder;

internal static class Output
{
    // Unix-seconds range supported by DateTimeOffset.FromUnixTimeSeconds.
    private const long MinUnixSeconds = -62135596800L; // 0001-01-01 UTC
    private const long MaxUnixSeconds =  253402300799L; // 9999-12-31 UTC

    public static void WriteSimplified(TextWriter w, Jwt jwt, VerifyOutcome? verify)
    {
        WriteHeaderSection(w, jwt);
        w.WriteLine();
        WritePayloadSection(w, jwt);
        w.WriteLine();
        WriteTimeStatus(w, jwt);
        if (verify is not null)
        {
            w.WriteLine();
            WriteVerifySection(w, verify);
        }
    }

    public static void WriteDetailed(TextWriter w, Jwt jwt, VerifyOutcome? verify)
    {
        WriteHeaderSection(w, jwt);
        w.WriteLine();
        WritePayloadSection(w, jwt);
        w.WriteLine();
        WriteTimeStatus(w, jwt);
        w.WriteLine();
        WriteRawSection(w, jwt);
        if (verify is not null)
        {
            w.WriteLine();
            WriteVerifySection(w, verify);
        }
    }

    /// <summary>
    /// Writes the value(s) at the given comma-separated query <paramref name="paths"/>, one per
    /// line in the order requested. Returns the index of the first path that did not resolve, or
    /// <c>-1</c> if every path matched.
    /// </summary>
    /// <param name="w">Destination writer (typically <see cref="Console.Out"/>).</param>
    /// <param name="jwt">The decoded JWT to query.</param>
    /// <param name="paths">Comma-separated query paths.</param>
    /// <param name="raw">If <c>true</c>, string scalars are emitted unwrapped (subject to a
    /// control-character safety check; see <see cref="FormatForCli"/>).</param>
    /// <param name="firstFailingPath">On not-found return, the original text of the path that
    /// did not resolve (so the caller can build a useful diagnostic without re-parsing).
    /// On <c>-1</c> return, empty.</param>
    /// <remarks>
    /// Atomic behaviour: nothing is written to <paramref name="w"/> until every path has been
    /// resolved AND every value has passed the <paramref name="raw"/>-mode safety check. On a
    /// missing path the method returns the path's index with <paramref name="w"/> untouched.
    /// On a control-character-bearing string value under <paramref name="raw"/>, the method
    /// throws <see cref="InvalidDataException"/> with <paramref name="w"/> untouched. This
    /// prevents a script that ignores the exit code from consuming partial output for a
    /// missing path, or terminal-injection bytes for a deliberately-malicious string scalar.
    /// </remarks>
    public static int WriteQueryResults(TextWriter w, Jwt jwt, string paths, bool raw, out string firstFailingPath)
    {
        var parsed = JwtQueryPath.ParseMany(paths);
        var formatted = new List<string>(parsed.Count);
        for (int i = 0; i < parsed.Count; i++)
        {
            if (!JwtQuery.TryQuery(jwt, parsed[i], out var el))
            {
                firstFailingPath = parsed[i].Original;
                return i;
            }
            formatted.Add(FormatForCli(parsed[i], el, raw));
        }
        foreach (var s in formatted)
            w.WriteLine(s);
        firstFailingPath = string.Empty;
        return -1;
    }

    /// <summary>
    /// Format a queried <see cref="JsonElement"/> for CLI output. In <paramref name="raw"/>
    /// mode, string scalars are returned unwrapped (without JSON quotes) — but only after a
    /// scan refuses any value containing ASCII C0/DEL/C1 control characters. The default
    /// (non-raw) path uses <see cref="JwtQuery.FormatJson(JsonElement)"/>, which always emits
    /// terminal-safe JSON with control characters escaped as <c>\\uXXXX</c>.
    /// </summary>
    /// <exception cref="InvalidDataException">In <paramref name="raw"/> mode, when the string
    /// value at <paramref name="path"/> contains a C0/DEL/C1 control character that would
    /// reach the terminal verbatim if printed.</exception>
    private static string FormatForCli(JwtQueryPath path, JsonElement el, bool raw)
    {
        if (!raw)
            return JwtQuery.FormatJson(el);

        if (el.ValueKind == JsonValueKind.String)
        {
            string s = el.GetString() ?? string.Empty;
            int badAt = IndexOfControlChar(s);
            if (badAt >= 0)
            {
                int code = s[badAt];
                throw new InvalidDataException(
                    $"Query value at '{path.Original}' contains an ASCII / C1 control character " +
                    $"(\\u{code:X4} at position {badAt}) and cannot be emitted in --raw mode without " +
                    "risk of terminal-control injection. Remove --raw to emit the JSON-escaped form.");
            }
            return s;
        }

        // Numbers, booleans, null, objects, arrays: FormatRaw already routes these through
        // FormatJson, which is terminal-safe via Utf8JsonWriter's default escaping policy.
        return JwtQuery.FormatRaw(el);
    }

    private static int IndexOfControlChar(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            // C0 controls (0x00..0x1F), DEL (0x7F), and C1 controls (0x80..0x9F).
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F))
                return i;
        }
        return -1;
    }

    private static void WriteHeaderSection(TextWriter w, Jwt jwt)
    {
        w.WriteLine("== HEADER ==");
        WriteClaims(w, jwt.Header.RootElement);
    }

    private static void WritePayloadSection(TextWriter w, Jwt jwt)
    {
        w.WriteLine("== PAYLOAD ==");
        WriteClaims(w, jwt.Payload.RootElement);
    }

    private static void WriteRawSection(TextWriter w, Jwt jwt)
    {
        w.WriteLine("== RAW ==");
        w.WriteLine($"header.segment    : {jwt.HeaderSegment}");
        w.WriteLine($"payload.segment   : {jwt.PayloadSegment}");
        w.WriteLine($"signature.segment : {(jwt.SignatureSegment.Length == 0 ? "(empty)" : jwt.SignatureSegment)}");
        w.WriteLine($"signature.bytes   : {(jwt.SignatureBytes.Length == 0 ? "(empty)" : Convert.ToHexString(jwt.SignatureBytes).ToLowerInvariant())}");
        w.WriteLine($"signing.input     : {Encoding.ASCII.GetString(jwt.SigningInput)}");
    }

    private static void WriteTimeStatus(TextWriter w, Jwt jwt)
    {
        w.WriteLine("== TIME STATUS ==");
        var now = DateTimeOffset.UtcNow;
        var payload = jwt.Payload.RootElement;

        bool hasIat = Jwt.TryGetUnixSeconds(payload, "iat", out long iat);
        bool hasNbf = Jwt.TryGetUnixSeconds(payload, "nbf", out long nbf);
        bool hasExp = Jwt.TryGetUnixSeconds(payload, "exp", out long exp);

        if (hasIat) w.WriteLine($"issued at (iat) : {FormatUnix(iat)}");
        if (hasNbf) w.WriteLine($"not before (nbf): {FormatUnix(nbf)}");
        if (hasExp) w.WriteLine($"expires (exp)   : {FormatUnix(exp)}");

        string status;
        if (hasNbf && IsInUnixRange(nbf) && now < DateTimeOffset.FromUnixTimeSeconds(nbf))
            status = "NOT YET VALID";
        else if (hasExp && IsInUnixRange(exp) && now > DateTimeOffset.FromUnixTimeSeconds(exp))
            status = "EXPIRED";
        else if (hasExp || hasNbf || hasIat)
            status = "VALID (time-wise)";
        else
            status = "UNKNOWN (no iat/nbf/exp claims)";

        w.WriteLine($"status          : {status}");
    }

    private static void WriteVerifySection(TextWriter w, VerifyOutcome v)
    {
        w.WriteLine("== SIGNATURE VERIFICATION ==");
        w.WriteLine($"algorithm : {v.Algorithm}");
        w.WriteLine($"result    : {(v.Verified ? "VALID \u2014 signature matches the supplied key." : "INVALID \u2014 signature does NOT match.")}");
        if (!v.Verified && !string.IsNullOrEmpty(v.Error))
            w.WriteLine($"detail    : {v.Error}");
    }

    private static void WriteClaims(TextWriter w, JsonElement obj)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            w.WriteLine($"(non-object value: {FormatValue(obj)})");
            return;
        }

        int nameWidth = 0;
        foreach (var p in obj.EnumerateObject())
        {
            int len = SafeName(p.Name).Length;
            if (len > nameWidth) nameWidth = len;
        }
        if (nameWidth > 24) nameWidth = 24;

        foreach (var p in obj.EnumerateObject())
        {
            string name = SafeName(p.Name);
            if (name.Length < nameWidth) name = name.PadRight(nameWidth);
            w.WriteLine($"{name} : {FormatValue(p.Value)}");
        }
    }

    private static string FormatValue(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                // GetRawText() returns the JSON-quoted form with all escapes preserved.
                // This prevents terminal-control-character injection from a malicious token.
                return el.GetRawText();
            case JsonValueKind.Number:
                return el.GetRawText();
            case JsonValueKind.True:  return "true";
            case JsonValueKind.False: return "false";
            case JsonValueKind.Null:  return "null";
            case JsonValueKind.Object:
            case JsonValueKind.Array:
                return PrettyJson(el);
            default:
                return el.GetRawText();
        }
    }

    private static string PrettyJson(JsonElement el)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            el.WriteTo(writer);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    /// Escape ASCII / C1 control characters in JSON property names so a malicious token
    /// cannot inject terminal escape sequences via header/payload key names.
    private static string SafeName(string name)
    {
        bool needs = false;
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)) { needs = true; break; }
        }
        if (!needs) return name;

        var sb = new StringBuilder(name.Length + 8);
        foreach (char c in name)
        {
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F))
                sb.Append('\\').Append('u').Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    private static bool IsInUnixRange(long seconds) =>
        seconds >= MinUnixSeconds && seconds <= MaxUnixSeconds;

    private static string FormatUnix(long seconds)
    {
        if (!IsInUnixRange(seconds))
            return string.Create(CultureInfo.InvariantCulture, $"{seconds} (out of representable range)");
        var dto = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return string.Create(CultureInfo.InvariantCulture, $"{seconds} ({dto.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC)");
    }
}
