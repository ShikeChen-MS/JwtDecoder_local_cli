using System.Text.Json;

namespace JwtDecoder.JwksFetcher;

/// <summary>
/// Parses and validates a JWKS document (RFC 7517) into a list of
/// <see cref="JwkRecord"/> instances suitable for signature verification.
/// </summary>
/// <remarks>
/// Hardening applied at parse time (see the JWKS companion design plan):
/// <list type="bullet">
/// <item>Strict JSON: <c>MaxDepth = 64</c>, no comments, no trailing commas,
/// recursive duplicate-property rejection at every object depth.</item>
/// <item>Overall size cap of <see cref="MaxJwksBytes"/>.</item>
/// <item>Only <c>kty=RSA</c> and <c>kty=EC</c> are accepted. <c>kty=oct</c>
/// is refused — symmetric secrets must not cross the network/PEM boundary.</item>
/// <item>Any key carrying a private component (RSA <c>d</c>/<c>p</c>/<c>q</c>/<c>dp</c>/<c>dq</c>/<c>qi</c>,
/// EC <c>d</c>) is refused — verification only needs the public key.</item>
/// <item>Remote-reference members <c>x5u</c> and <c>jku</c> are refused; <c>x5c</c>
/// is silently ignored (trust is anchored at the JWKS URL itself).</item>
/// <item><c>use</c> if present must be <c>"sig"</c>. <c>key_ops</c> if present
/// must contain <c>"verify"</c>. Both must be consistent if both present.</item>
/// <item>RSA modulus must be at least <see cref="MinRsaModulusBits"/> bits,
/// exponent must be odd and ≥ 3.</item>
/// <item>EC <c>crv</c> must be one of <c>P-256</c>/<c>P-384</c>/<c>P-521</c>;
/// <c>x</c>/<c>y</c> coordinate byte length must match the curve exactly.</item>
/// </list>
/// </remarks>
public static class JwksDocument
{
    /// <summary>JWKS documents in production are usually &lt; 8 KiB. 256 KiB is a generous bound.</summary>
    public const int MaxJwksBytes = 256 * 1024;

    /// <summary>Maximum base64url-encoded length of the RSA modulus (defends against absurd inputs).</summary>
    public const int MaxRsaModulusBase64Chars = 2048;

    /// <summary>Maximum base64url-encoded length of the RSA exponent.</summary>
    public const int MaxRsaExponentBase64Chars = 16;

    /// <summary>Minimum acceptable RSA modulus bit length.</summary>
    public const int MinRsaModulusBits = 2048;

    /// <summary>Parse a JWKS document and return validated <see cref="JwkRecord"/> entries.</summary>
    /// <exception cref="InvalidDataException">The document is structurally invalid, oversized, or contains a refused key.</exception>
    public static IReadOnlyList<JwkRecord> Parse(ReadOnlySpan<byte> jwksJson)
    {
        if (jwksJson.Length > MaxJwksBytes)
            throw new InvalidDataException($"JWKS document exceeds maximum size of {MaxJwksBytes:N0} bytes.");
        if (jwksJson.IsEmpty)
            throw new InvalidDataException("JWKS document is empty.");

        // We do dup-key rejection ourselves (JsonDocument silently keeps the last value).
        RejectDuplicateKeysRecursive(jwksJson, "JWKS");

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(jwksJson.ToArray(), new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = 64,
            });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("JWKS document is not valid JSON: " + ex.Message, ex);
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("JWKS root must be a JSON object.");

            if (!doc.RootElement.TryGetProperty("keys", out var keysEl))
                throw new InvalidDataException("JWKS document is missing required 'keys' property.");
            if (keysEl.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("JWKS 'keys' must be a JSON array.");

            var keys = new List<JwkRecord>();
            int idx = 0;
            foreach (var el in keysEl.EnumerateArray())
            {
                if (el.ValueKind != JsonValueKind.Object)
                    throw new InvalidDataException($"JWKS 'keys[{idx}]' is not a JSON object.");
                keys.Add(ParseSingleJwk(el, idx));
                idx++;
            }
            if (keys.Count == 0)
                throw new InvalidDataException("JWKS 'keys' array is empty.");

            return keys;
        }
    }

    private static JwkRecord ParseSingleJwk(JsonElement el, int idx)
    {
        // --- Reject remote-reference members up front (round-2 review). ---
        if (el.TryGetProperty("x5u", out _))
            throw new InvalidDataException($"JWKS 'keys[{idx}]' carries an 'x5u' member; remote-reference key members are refused.");
        if (el.TryGetProperty("jku", out _))
            throw new InvalidDataException($"JWKS 'keys[{idx}]' carries a 'jku' member; remote-reference key members are refused.");
        // x5c is silently ignored.

        // --- kty (required). ---
        if (!el.TryGetProperty("kty", out var ktyEl) || ktyEl.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"JWKS 'keys[{idx}]' is missing required string member 'kty'.");
        string kty = ktyEl.GetString() ?? "";
        if (kty.Length == 0)
            throw new InvalidDataException($"JWKS 'keys[{idx}].kty' is empty.");
        if (kty == "oct")
            throw new InvalidDataException($"JWKS 'keys[{idx}]' is kty=oct; symmetric keys are refused (they would violate the public-key-PEM boundary).");
        if (kty != "RSA" && kty != "EC")
            throw new InvalidDataException($"JWKS 'keys[{idx}].kty' is '{kty}'; only 'RSA' and 'EC' are supported.");

        // --- Refuse any private components, regardless of kty. ---
        foreach (var priv in new[] { "d", "p", "q", "dp", "dq", "qi" })
        {
            if (el.TryGetProperty(priv, out _))
                throw new InvalidDataException($"JWKS 'keys[{idx}]' carries private component '{priv}'; private keys are refused (verification only needs the public key).");
        }

        // --- Optional kid/alg/use. ---
        string? kid = ReadOptionalString(el, "kid", idx);
        string? alg = ReadOptionalString(el, "alg", idx);
        string? use = ReadOptionalString(el, "use", idx);
        if (use is not null && use != "sig")
            throw new InvalidDataException($"JWKS 'keys[{idx}].use' is '{use}'; only 'sig' is acceptable for signature verification.");

        // --- Optional key_ops. ---
        IReadOnlyList<string>? keyOps = null;
        if (el.TryGetProperty("key_ops", out var keyOpsEl))
        {
            if (keyOpsEl.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException($"JWKS 'keys[{idx}].key_ops' must be a JSON array.");
            var ops = new List<string>();
            foreach (var op in keyOpsEl.EnumerateArray())
            {
                if (op.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException($"JWKS 'keys[{idx}].key_ops' contains a non-string element.");
                ops.Add(op.GetString() ?? "");
            }
            if (!ops.Contains("verify", StringComparer.Ordinal))
                throw new InvalidDataException($"JWKS 'keys[{idx}].key_ops' does not contain 'verify'; cannot be used for signature verification.");
            keyOps = ops;
        }

        // --- kty-specific fields. ---
        if (kty == "RSA")
        {
            string n = RequireString(el, "n", idx);
            string e = RequireString(el, "e", idx);
            ValidateRsaModulus(n, idx);
            ValidateRsaExponent(e, idx);
            return new JwkRecord
            {
                Kty = "RSA",
                Kid = kid,
                Alg = alg,
                Use = use,
                KeyOps = keyOps,
                N = n,
                E = e,
            };
        }
        else // "EC"
        {
            string crv = RequireString(el, "crv", idx);
            string x = RequireString(el, "x", idx);
            string y = RequireString(el, "y", idx);
            ValidateEcCoordinates(crv, x, y, idx);
            return new JwkRecord
            {
                Kty = "EC",
                Kid = kid,
                Alg = alg,
                Use = use,
                KeyOps = keyOps,
                Crv = crv,
                X = x,
                Y = y,
            };
        }
    }

    private static string? ReadOptionalString(JsonElement el, string name, int idx)
    {
        if (!el.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"JWKS 'keys[{idx}].{name}' must be a string when present.");
        return v.GetString();
    }

    private static string RequireString(JsonElement el, string name, int idx)
    {
        if (!el.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"JWKS 'keys[{idx}]' is missing required string member '{name}'.");
        string s = v.GetString() ?? "";
        if (s.Length == 0)
            throw new InvalidDataException($"JWKS 'keys[{idx}].{name}' is empty.");
        return s;
    }

    private static void ValidateRsaModulus(string nB64, int idx)
    {
        if (nB64.Length > MaxRsaModulusBase64Chars)
            throw new InvalidDataException($"JWKS 'keys[{idx}].n' base64url length {nB64.Length} exceeds maximum {MaxRsaModulusBase64Chars}.");

        byte[] nBytes;
        try { nBytes = Base64UrlCodec.Decode(nB64); }
        catch (FormatException ex) { throw new InvalidDataException($"JWKS 'keys[{idx}].n' is not valid base64url: {ex.Message}", ex); }

        int bits = ComputeBigEndianBitLength(nBytes);
        if (bits < MinRsaModulusBits)
            throw new InvalidDataException($"JWKS 'keys[{idx}].n' is a {bits}-bit modulus; minimum accepted is {MinRsaModulusBits} bits.");
    }

    private static void ValidateRsaExponent(string eB64, int idx)
    {
        if (eB64.Length > MaxRsaExponentBase64Chars)
            throw new InvalidDataException($"JWKS 'keys[{idx}].e' base64url length {eB64.Length} exceeds maximum {MaxRsaExponentBase64Chars}.");

        byte[] eBytes;
        try { eBytes = Base64UrlCodec.Decode(eB64); }
        catch (FormatException ex) { throw new InvalidDataException($"JWKS 'keys[{idx}].e' is not valid base64url: {ex.Message}", ex); }

        // Strip leading zeros.
        int firstNonZero = -1;
        for (int i = 0; i < eBytes.Length; i++)
        {
            if (eBytes[i] != 0) { firstNonZero = i; break; }
        }
        if (firstNonZero < 0)
            throw new InvalidDataException($"JWKS 'keys[{idx}].e' decodes to zero; RSA exponent must be ≥ 3 and odd.");

        int effLen = eBytes.Length - firstNonZero;
        byte lsb = eBytes[eBytes.Length - 1];
        if ((lsb & 1) == 0)
            throw new InvalidDataException($"JWKS 'keys[{idx}].e' is an even number; RSA exponent must be odd.");
        if (effLen == 1 && eBytes[firstNonZero] < 3)
            throw new InvalidDataException($"JWKS 'keys[{idx}].e' is {eBytes[firstNonZero]}; RSA exponent must be ≥ 3.");
    }

    private static void ValidateEcCoordinates(string crv, string x, string y, int idx)
    {
        int expectedBytes = crv switch
        {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => throw new InvalidDataException($"JWKS 'keys[{idx}].crv' is '{crv}'; only 'P-256', 'P-384', 'P-521' are supported."),
        };

        byte[] xBytes, yBytes;
        try { xBytes = Base64UrlCodec.Decode(x); }
        catch (FormatException ex) { throw new InvalidDataException($"JWKS 'keys[{idx}].x' is not valid base64url: {ex.Message}", ex); }
        try { yBytes = Base64UrlCodec.Decode(y); }
        catch (FormatException ex) { throw new InvalidDataException($"JWKS 'keys[{idx}].y' is not valid base64url: {ex.Message}", ex); }

        if (xBytes.Length != expectedBytes)
            throw new InvalidDataException($"JWKS 'keys[{idx}].x' is {xBytes.Length} bytes; curve {crv} requires {expectedBytes}.");
        if (yBytes.Length != expectedBytes)
            throw new InvalidDataException($"JWKS 'keys[{idx}].y' is {yBytes.Length} bytes; curve {crv} requires {expectedBytes}.");
    }

    private static int ComputeBigEndianBitLength(ReadOnlySpan<byte> bytes)
    {
        int i = 0;
        while (i < bytes.Length && bytes[i] == 0) i++;
        if (i == bytes.Length) return 0;
        int leadingZerosInTopByte = 0;
        byte top = bytes[i];
        while ((top & 0x80) == 0) { leadingZerosInTopByte++; top <<= 1; }
        return (bytes.Length - i) * 8 - leadingZerosInTopByte;
    }

    private static void RejectDuplicateKeysRecursive(ReadOnlySpan<byte> jsonBytes, string contextName)
    {
        var reader = new Utf8JsonReader(jsonBytes, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 64,
        });

        var stack = new Stack<HashSet<string>>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        stack.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.EndObject:
                        if (stack.Count > 0) stack.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        if (stack.Count > 0)
                        {
                            string name = reader.GetString() ?? "";
                            if (!stack.Peek().Add(name))
                                throw new InvalidDataException($"{contextName} contains duplicate JSON property '{name}'.");
                        }
                        break;
                }
            }
        }
        catch (JsonException ex)
        {
            // Defer to the JsonDocument.Parse error path for consistent messages.
            throw new InvalidDataException($"{contextName} is not valid JSON: " + ex.Message, ex);
        }
    }
}
