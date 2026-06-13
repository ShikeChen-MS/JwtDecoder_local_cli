using System.Text;
using System.Text.Json;

namespace JwtDecoder.Core;

/// <summary>
/// Which top-level segment of the JWT a <see cref="JwtQueryPath"/> targets.
/// </summary>
public enum JwtScope
{
    /// <summary>The JWT payload (claims).</summary>
    Payload,
    /// <summary>The JOSE header.</summary>
    Header,
}

/// <summary>
/// A single segment of a parsed query path: either an object property name or an array index.
/// </summary>
/// <remarks>
/// A segment is a property when <see cref="Name"/> is non-null. Otherwise it is an array index
/// and <see cref="Index"/> holds the (non-negative) position.
/// </remarks>
public readonly record struct PathSegment(string? Name, int Index)
{
    /// <summary>True if this segment targets an array index.</summary>
    public bool IsIndex => Name is null;

    /// <summary>True if this segment targets an object property.</summary>
    public bool IsProperty => Name is not null;

    /// <summary>Creates a property-name segment.</summary>
    public static PathSegment Property(string name) => new(name, -1);

    /// <summary>Creates an array-index segment.</summary>
    public static PathSegment IndexAt(int index) => new(null, index);

    /// <inheritdoc/>
    public override string ToString() => IsIndex ? $"[{Index}]" : Name!;
}

/// <summary>
/// A parsed JWT query path: a <see cref="JwtScope"/> (payload or header) plus zero or more
/// <see cref="PathSegment"/>s walking into that JSON tree.
/// </summary>
/// <remarks>
/// <para>Grammar (informal):</para>
/// <code>
/// path     = segment ('.' segment | '[' index ']')*
/// segment  = unquoted | '"' quoted '"'
/// unquoted = [A-Za-z0-9_-]+
/// quoted   = any chars except unescaped '"';  \\"  and  \\\\  are recognized
/// index    = digits (non-negative)
/// </code>
/// <para>
/// If the first segment is exactly <c>header</c> or <c>payload</c>, it selects the scope and is
/// consumed. Otherwise the scope defaults to <see cref="JwtScope.Payload"/> and the first segment
/// is treated as a payload claim name — this is the "shorthand" form (e.g. <c>sub</c> ≡
/// <c>payload.sub</c>). An explicit scope keyword cannot be immediately followed by an array
/// index — JOSE header and payload are required to be JSON objects, so <c>payload[0]</c> /
/// <c>header[0]</c> are syntax errors.
/// </para>
/// <para>
/// DoS hardening: <see cref="Parse"/> and <see cref="ParseMany"/> refuse inputs longer than
/// <see cref="MaxQueryChars"/>, and refuse to produce more than <see cref="MaxSegments"/>
/// segments per path. This matches the bounded-input policy applied across the rest of the
/// library (token ≤ 1 MiB, key file ≤ 64 KiB, decoded segment ≤ 256 KiB).
/// </para>
/// </remarks>
public sealed class JwtQueryPath
{
    /// <summary>Maximum length, in chars, of a query path text. Real query paths are well under
    /// 100 chars; 4 KiB is a generous, bounded ceiling that prevents memory-exhaustion attacks
    /// from library callers passing externally-controlled path strings.</summary>
    public const int MaxQueryChars = 4 * 1024;

    /// <summary>Maximum number of segments produced from a single path. A pathological input
    /// like <c>a.a.a.a...</c> would otherwise expand a <see cref="List{T}"/> indefinitely.</summary>
    public const int MaxSegments = 256;

    /// <summary>The scope (payload or header) this path targets.</summary>
    public JwtScope Scope { get; }

    /// <summary>The segments to walk after entering the scope. May be empty
    /// (in which case the whole scope object is selected).</summary>
    public IReadOnlyList<PathSegment> Segments { get; }

    /// <summary>The original raw path text (after trimming).</summary>
    public string Original { get; }

    private JwtQueryPath(JwtScope scope, IReadOnlyList<PathSegment> segments, string original)
    {
        Scope = scope;
        Segments = segments;
        Original = original;
    }

    /// <summary>
    /// Parse a single query path. Throws <see cref="FormatException"/> on any malformed input or
    /// when <paramref name="path"/> exceeds <see cref="MaxQueryChars"/>.
    /// </summary>
    public static JwtQueryPath Parse(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (path.Length > MaxQueryChars)
            throw new FormatException($"Query path exceeds maximum supported length ({MaxQueryChars:N0} chars).");
        string raw = path.Trim();
        if (raw.Length == 0)
            throw new FormatException("Query path is empty.");
        return ParseInternal(raw);
    }

    /// <summary>
    /// Parse a comma-separated list of query paths. A comma inside a quoted segment or inside
    /// <c>[...]</c> does not split. Returns at least one path; throws <see cref="FormatException"/>
    /// if any sub-path is malformed or if the overall text exceeds <see cref="MaxQueryChars"/>.
    /// </summary>
    public static IReadOnlyList<JwtQueryPath> ParseMany(string commaSeparated)
    {
        ArgumentNullException.ThrowIfNull(commaSeparated);
        if (commaSeparated.Length > MaxQueryChars)
            throw new FormatException($"Query path list exceeds maximum supported length ({MaxQueryChars:N0} chars).");

        var paths = new List<JwtQueryPath>();
        int start = 0;
        bool inQuote = false;
        bool escape = false;
        int bracket = 0;

        for (int i = 0; i < commaSeparated.Length; i++)
        {
            char c = commaSeparated[i];
            if (escape) { escape = false; continue; }
            if (inQuote)
            {
                if (c == '\\') { escape = true; continue; }
                if (c == '"')  { inQuote = false; }
                continue;
            }
            if (c == '"') { inQuote = true; continue; }
            if (c == '[') { bracket++; continue; }
            if (c == ']') { if (bracket > 0) bracket--; continue; }
            if (c == ',' && bracket == 0)
            {
                string slice = commaSeparated.Substring(start, i - start).Trim();
                if (slice.Length == 0)
                    throw new FormatException("Empty query path between commas.");
                paths.Add(ParseInternal(slice));
                start = i + 1;
            }
        }

        if (inQuote)  throw new FormatException("Unterminated quoted segment in query path.");
        if (bracket != 0) throw new FormatException("Mismatched '[' / ']' in query path.");

        string last = commaSeparated.Substring(start).Trim();
        if (last.Length == 0)
        {
            if (paths.Count == 0)
                throw new FormatException("Query path is empty.");
            throw new FormatException("Empty query path after trailing comma.");
        }
        paths.Add(ParseInternal(last));
        return paths;
    }

    private static JwtQueryPath ParseInternal(string raw)
    {
        int pos = 0;
        var (firstSeg, nextPos) = ReadSegment(raw, pos);
        pos = nextPos;

        JwtScope scope;
        bool explicitScope;
        var segments = new List<PathSegment>();
        if (firstSeg.IsProperty && (firstSeg.Name == "payload" || firstSeg.Name == "header"))
        {
            scope = firstSeg.Name == "header" ? JwtScope.Header : JwtScope.Payload;
            explicitScope = true;
        }
        else
        {
            scope = JwtScope.Payload;
            explicitScope = false;
            segments.Add(firstSeg);
        }

        // JOSE header and payload are required to be JSON objects (enforced by Jwt.Parse), so
        // indexing the root scope (e.g. `payload[0]`) can never resolve. Reject as syntax error
        // at parse time rather than letting it silently become "not found" at query time.
        if (explicitScope && pos < raw.Length && raw[pos] == '[')
            throw new FormatException(
                $"Query path '{raw}' indexes the '{(scope == JwtScope.Header ? "header" : "payload")}' " +
                "root as an array; the root is required to be a JSON object. Use a property segment first " +
                $"(e.g. '{(scope == JwtScope.Header ? "header" : "payload")}.someProperty[0]').");

        while (pos < raw.Length)
        {
            if (segments.Count >= MaxSegments)
                throw new FormatException(
                    $"Query path '{raw}' exceeds maximum segment count ({MaxSegments}).");

            char c = raw[pos];
            if (c == '.')
            {
                pos++;
                var (seg, next) = ReadSegment(raw, pos);
                segments.Add(seg);
                pos = next;
            }
            else if (c == '[')
            {
                int end = raw.IndexOf(']', pos);
                if (end < 0)
                    throw new FormatException($"Unterminated '[' in query path '{raw}'.");
                string num = raw.Substring(pos + 1, end - pos - 1);
                if (num.Length == 0)
                    throw new FormatException($"Empty array index in query path '{raw}'.");
                if (!int.TryParse(num, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int idx) || idx < 0)
                    throw new FormatException($"Invalid array index '[{num}]' in query path '{raw}'.");
                segments.Add(PathSegment.IndexAt(idx));
                pos = end + 1;
            }
            else
            {
                throw new FormatException($"Unexpected character '{c}' at position {pos} in query path '{raw}'.");
            }
        }

        return new JwtQueryPath(scope, segments, raw);
    }

    private static (PathSegment seg, int nextPos) ReadSegment(string raw, int pos)
    {
        if (pos >= raw.Length)
            throw new FormatException($"Unexpected end of query path '{raw}'.");

        char c = raw[pos];
        if (c == '"')
        {
            var sb = new StringBuilder();
            pos++;
            while (pos < raw.Length)
            {
                char cc = raw[pos];
                if (cc == '\\')
                {
                    if (pos + 1 >= raw.Length)
                        throw new FormatException($"Unterminated escape in quoted segment of '{raw}'.");
                    char esc = raw[pos + 1];
                    char appended = esc switch
                    {
                        '"'  => '"',
                        '\\' => '\\',
                        _    => throw new FormatException($"Invalid escape '\\{esc}' in quoted segment of '{raw}'. Only \\\" and \\\\ are recognized."),
                    };
                    sb.Append(appended);
                    pos += 2;
                }
                else if (cc == '"')
                {
                    pos++;
                    if (sb.Length == 0)
                        throw new FormatException($"Empty quoted segment in query path '{raw}'.");
                    return (PathSegment.Property(sb.ToString()), pos);
                }
                else
                {
                    sb.Append(cc);
                    pos++;
                }
            }
            throw new FormatException($"Unterminated quoted segment in query path '{raw}'.");
        }
        else
        {
            int start = pos;
            while (pos < raw.Length)
            {
                char cc = raw[pos];
                if (cc == '.' || cc == '[') break;
                if (!IsUnquotedChar(cc))
                    throw new FormatException(
                        $"Invalid character '{cc}' at position {pos} in query path '{raw}'. Quote the segment with double quotes to allow it.");
                pos++;
            }
            if (pos == start)
                throw new FormatException($"Empty path segment in query path '{raw}'.");
            return (PathSegment.Property(raw.Substring(start, pos - start)), pos);
        }
    }

    private static bool IsUnquotedChar(char c) =>
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '_' || c == '-';

    /// <inheritdoc/>
    public override string ToString() => Original;
}

/// <summary>
/// Walks a parsed <see cref="JwtQueryPath"/> through a decoded <see cref="Jwt"/>'s header or
/// payload and returns the matched <see cref="JsonElement"/>, plus helpers for formatting the
/// result in JSON-canonical or raw form for display.
/// </summary>
/// <remarks>
/// <para>
/// "Not found" means the path could not be resolved: an intermediate property is missing, an
/// index is out of bounds, or a segment type does not match the current node kind (e.g. asking
/// for a property name on a JSON array). A JSON <c>null</c> value at the target path is a
/// successful match — <see cref="TryQuery(Jwt, JwtQueryPath, out JsonElement)"/> returns true
/// and yields a <see cref="JsonValueKind.Null"/> element.
/// </para>
/// <para>
/// This type is AOT-safe and does not use reflection-based serialization.
/// </para>
/// </remarks>
public static class JwtQuery
{
    /// <summary>
    /// Try to resolve a textual query path against <paramref name="jwt"/>.
    /// </summary>
    /// <param name="jwt">The decoded JWT.</param>
    /// <param name="path">A query path (see <see cref="JwtQueryPath"/> for the grammar).</param>
    /// <param name="value">On success, the matched element. The element is backed by the JWT's
    /// internal <see cref="JsonDocument"/>s and is valid only until <see cref="Jwt.Dispose"/>
    /// is called. Call <see cref="JsonElement.Clone"/> if you need it to outlive the JWT.</param>
    /// <returns><c>true</c> if the path resolved (including to a JSON <c>null</c>); <c>false</c>
    /// if the path did not match.</returns>
    /// <exception cref="ArgumentNullException">If <paramref name="jwt"/> or <paramref name="path"/> is null.</exception>
    /// <exception cref="FormatException">If <paramref name="path"/> is syntactically invalid.</exception>
    public static bool TryQuery(Jwt jwt, string path, out JsonElement value)
        => TryQuery(jwt, JwtQueryPath.Parse(path), out value);

    /// <summary>
    /// Try to resolve a pre-parsed query path against <paramref name="jwt"/>.
    /// </summary>
    public static bool TryQuery(Jwt jwt, JwtQueryPath path, out JsonElement value)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(path);

        JsonElement current = path.Scope == JwtScope.Header
            ? jwt.Header.RootElement
            : jwt.Payload.RootElement;

        foreach (var seg in path.Segments)
        {
            if (seg.IsProperty)
            {
                if (current.ValueKind != JsonValueKind.Object)
                {
                    value = default;
                    return false;
                }
                if (!current.TryGetProperty(seg.Name!, out var child))
                {
                    value = default;
                    return false;
                }
                current = child;
            }
            else
            {
                if (current.ValueKind != JsonValueKind.Array)
                {
                    value = default;
                    return false;
                }
                int len = current.GetArrayLength();
                if (seg.Index < 0 || seg.Index >= len)
                {
                    value = default;
                    return false;
                }
                int i = 0;
                JsonElement match = default;
                bool found = false;
                foreach (var el in current.EnumerateArray())
                {
                    if (i++ == seg.Index) { match = el; found = true; break; }
                }
                if (!found) { value = default; return false; }
                current = match;
            }
        }

        value = current;
        return true;
    }

    /// <summary>
    /// Resolve a textual query path against <paramref name="jwt"/>, returning <c>null</c> if not found.
    /// </summary>
    public static JsonElement? Query(Jwt jwt, string path)
        => TryQuery(jwt, path, out var v) ? v : null;

    /// <summary>
    /// Resolve a pre-parsed query path against <paramref name="jwt"/>, returning <c>null</c> if not found.
    /// </summary>
    public static JsonElement? Query(Jwt jwt, JwtQueryPath path)
        => TryQuery(jwt, path, out var v) ? v : null;

    /// <summary>
    /// Render <paramref name="value"/> as a compact JSON string. Strings are JSON-quoted with
    /// all escapes preserved; numbers, booleans, and <c>null</c> use their JSON literal form;
    /// objects and arrays are emitted as single-line JSON.
    /// </summary>
    /// <remarks>
    /// This is the "safe" rendering: control characters in string values remain as <c>\\uXXXX</c>
    /// escapes and cannot be used to inject terminal control sequences.
    /// </remarks>
    public static string FormatJson(JsonElement value)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = false }))
        {
            value.WriteTo(writer);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    /// <summary>
    /// Render <paramref name="value"/> in "raw" form: string scalars are returned unwrapped
    /// (without surrounding JSON quotes, with JSON escapes decoded). All other kinds fall back
    /// to <see cref="FormatJson(JsonElement)"/>.
    /// </summary>
    /// <remarks>
    /// Strings emitted in raw form may contain any code point that was in the source token —
    /// including ASCII control characters. Do not write raw-formatted output directly to a
    /// terminal if you are processing tokens of unknown provenance.
    /// </remarks>
    public static string FormatRaw(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Null   => "null",
            _ => FormatJson(value),
        };
    }
}
