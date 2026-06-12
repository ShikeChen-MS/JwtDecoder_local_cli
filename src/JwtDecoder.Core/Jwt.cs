using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtDecoder.Core;

/// <summary>
/// A parsed JSON Web Token (JWS form).
/// </summary>
/// <remarks>
/// Security:
/// <list type="bullet">
/// <item>All raw byte buffers (header / payload / signature / signing-input) are zeroed in <see cref="Dispose"/>.</item>
/// <item>Strict size limits prevent unbounded memory consumption from adversarial input.</item>
/// <item>Duplicate JOSE header / payload property names are rejected to avoid parser-differential ambiguity.</item>
/// <item>The <c>alg</c> header is required to be a non-empty string.</item>
/// </list>
/// </remarks>
public sealed class Jwt : IDisposable
{
    /// <summary>Real-world JWTs are typically well under 100 KB. 1 MiB is a generous, bounded ceiling.</summary>
    public const int MaxTokenChars = 1 * 1024 * 1024;

    /// <summary>Each base64url segment after decoding is capped to bound JSON parser cost.</summary>
    public const int MaxDecodedSegmentBytes = 256 * 1024;

    public string HeaderSegment { get; }
    public string PayloadSegment { get; }
    public string SignatureSegment { get; }

    public byte[] HeaderJsonBytes { get; }
    public byte[] PayloadJsonBytes { get; }
    public byte[] SignatureBytes { get; }

    /// <summary>ASCII bytes of "headerSegment.payloadSegment" — the signed input.</summary>
    public byte[] SigningInput { get; }

    public JsonDocument Header { get; }
    public JsonDocument Payload { get; }

    public string Algorithm { get; }
    public string? Type { get; }

    private bool _disposed;

    private Jwt(
        string h, string p, string s,
        byte[] hBytes, byte[] pBytes, byte[] sBytes,
        byte[] signingInput,
        JsonDocument header, JsonDocument payload,
        string alg, string? typ)
    {
        HeaderSegment = h; PayloadSegment = p; SignatureSegment = s;
        HeaderJsonBytes = hBytes; PayloadJsonBytes = pBytes; SignatureBytes = sBytes;
        SigningInput = signingInput;
        Header = header; Payload = payload;
        Algorithm = alg; Type = typ;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Header.Dispose();
        Payload.Dispose();

        CryptographicOperations.ZeroMemory(HeaderJsonBytes);
        CryptographicOperations.ZeroMemory(PayloadJsonBytes);
        CryptographicOperations.ZeroMemory(SignatureBytes);
        CryptographicOperations.ZeroMemory(SigningInput);
    }

    /// <summary>
    /// Parse a JWT string. Throws <see cref="FormatException"/> for any malformed input.
    /// Accepts a leading <c>Bearer </c> prefix and surrounding quotes for convenience.
    /// </summary>
    public static Jwt Parse(string token)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.Length > MaxTokenChars)
            throw new FormatException($"Token exceeds maximum supported length ({MaxTokenChars:N0} chars).");

        string trimmed = StripBearerAndWhitespace(token);

        string[] parts = trimmed.Split('.');
        if (parts.Length == 5)
            throw new FormatException("This appears to be a JWE (encrypted token), which is not supported. Only JWS (signed) tokens can be decoded.");
        if (parts.Length != 3)
            throw new FormatException($"A JWT must have 3 segments separated by '.', got {parts.Length}.");
        if (parts[0].Length == 0 || parts[1].Length == 0)
            throw new FormatException("JWT header or payload segment is empty.");

        byte[]? headerBytes = null;
        byte[]? payloadBytes = null;
        byte[]? sigBytes = null;
        byte[]? signingInput = null;
        JsonDocument? header = null;
        JsonDocument? payload = null;

        try
        {
            headerBytes  = Base64UrlDecode(parts[0], "header");
            payloadBytes = Base64UrlDecode(parts[1], "payload");
            sigBytes     = parts[2].Length == 0 ? Array.Empty<byte>() : Base64UrlDecode(parts[2], "signature");

            try { header  = JsonDocument.Parse(headerBytes); }
            catch (JsonException ex) { throw new FormatException("JWT header is not valid JSON: " + ex.Message, ex); }
            try { payload = JsonDocument.Parse(payloadBytes); }
            catch (JsonException ex) { throw new FormatException("JWT payload is not valid JSON: " + ex.Message, ex); }

            if (header.RootElement.ValueKind != JsonValueKind.Object)
                throw new FormatException("JWT header must be a JSON object.");
            if (payload.RootElement.ValueKind != JsonValueKind.Object)
                throw new FormatException("JWT payload must be a JSON object.");

            RejectDuplicateKeys(headerBytes, "header");
            RejectDuplicateKeys(payloadBytes, "payload");

            if (!header.RootElement.TryGetProperty("alg", out var algEl) ||
                algEl.ValueKind != JsonValueKind.String)
                throw new FormatException("JWT header is missing required string parameter 'alg'.");
            string alg = algEl.GetString() ?? string.Empty;
            if (alg.Length == 0)
                throw new FormatException("JWT header 'alg' is empty.");

            string? typ = null;
            if (header.RootElement.TryGetProperty("typ", out var typEl) && typEl.ValueKind == JsonValueKind.String)
                typ = typEl.GetString();

            signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);

            var jwt = new Jwt(
                parts[0], parts[1], parts[2],
                headerBytes, payloadBytes, sigBytes,
                signingInput,
                header, payload,
                alg, typ);

            headerBytes = payloadBytes = sigBytes = signingInput = null;
            header = payload = null;
            return jwt;
        }
        catch
        {
            header?.Dispose();
            payload?.Dispose();
            if (headerBytes  is not null) CryptographicOperations.ZeroMemory(headerBytes);
            if (payloadBytes is not null) CryptographicOperations.ZeroMemory(payloadBytes);
            if (sigBytes     is not null) CryptographicOperations.ZeroMemory(sigBytes);
            if (signingInput is not null) CryptographicOperations.ZeroMemory(signingInput);
            throw;
        }
    }

    /// <summary>
    /// Try to read a numeric claim as Unix seconds. Returns false if missing or wrong type.
    /// Accepts both number and numeric-string representations.
    /// </summary>
    public static bool TryGetUnixSeconds(JsonElement obj, string name, out long seconds)
    {
        seconds = 0;
        if (obj.ValueKind != JsonValueKind.Object) return false;
        if (!obj.TryGetProperty(name, out var el)) return false;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out seconds)) return true;
        if (el.ValueKind == JsonValueKind.String && long.TryParse(el.GetString(), out seconds)) return true;
        return false;
    }

    private static string StripBearerAndWhitespace(string token)
    {
        string t = token.Trim().Trim('"', '\'');
        if (t.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            t = t.Substring("Bearer ".Length).TrimStart();
        return t;
    }

    private static void RejectDuplicateKeys(byte[] jsonBytes, string segmentName)
    {
        var reader = new Utf8JsonReader(jsonBytes,
            new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = 64,
            });

        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        int depth = 1;
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject || reader.TokenType == JsonTokenType.StartArray)
            { depth++; continue; }
            if (reader.TokenType == JsonTokenType.EndObject || reader.TokenType == JsonTokenType.EndArray)
            { depth--; if (depth == 0) break; continue; }
            if (depth == 1 && reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString() ?? string.Empty;
                if (!seen.Add(name))
                    throw new FormatException($"JWT {segmentName} contains duplicate JSON property '{name}'.");
            }
        }
    }

    private static byte[] Base64UrlDecode(string input, string segmentName)
    {
        int maxEncoded = ((MaxDecodedSegmentBytes + 2) / 3) * 4 + 4;
        if (input.Length > maxEncoded)
            throw new FormatException($"JWT {segmentName} segment exceeds maximum size.");

        int paddedLen = input.Length + ((4 - (input.Length % 4)) % 4);

        char[]? rented = null;
        Span<char> buf = paddedLen <= 512
            ? stackalloc char[512]
            : (rented = ArrayPool<char>.Shared.Rent(paddedLen)).AsSpan();
        buf = buf.Slice(0, paddedLen);

        try
        {
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                buf[i] = c switch { '-' => '+', '_' => '/', _ => c };
            }
            for (int i = input.Length; i < paddedLen; i++) buf[i] = '=';

            int maxBytes = (paddedLen / 4) * 3;
            byte[] output = new byte[maxBytes];
            if (!Convert.TryFromBase64Chars(buf, output, out int written))
            {
                CryptographicOperations.ZeroMemory(output);
                throw new FormatException($"JWT {segmentName} segment is not valid base64url.");
            }

            if (written == maxBytes) return output;

            byte[] trimmed = new byte[written];
            output.AsSpan(0, written).CopyTo(trimmed);
            CryptographicOperations.ZeroMemory(output);
            return trimmed;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buf));
            if (rented is not null) ArrayPool<char>.Shared.Return(rented);
        }
    }
}
