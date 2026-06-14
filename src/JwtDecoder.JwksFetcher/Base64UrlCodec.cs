namespace JwtDecoder.JwksFetcher;

/// <summary>
/// base64url codec for JWK field values (n, e, x, y, etc.).
/// </summary>
/// <remarks>
/// net8.0 does not ship <c>System.Buffers.Text.Base64Url</c> (added in .NET 9),
/// so we provide a minimal implementation that defers the actual base64 work to
/// the BCL after translating the URL-safe alphabet and padding.
/// </remarks>
internal static class Base64UrlCodec
{
    public static byte[] Decode(string input)
    {
        if (string.IsNullOrEmpty(input))
            throw new FormatException("base64url input is empty.");

        int paddedLen = input.Length + ((4 - (input.Length % 4)) % 4);
        char[] buf = new char[paddedLen];
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            buf[i] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c,
            };
        }
        for (int i = input.Length; i < paddedLen; i++) buf[i] = '=';

        try
        {
            return Convert.FromBase64CharArray(buf, 0, paddedLen);
        }
        catch (FormatException ex)
        {
            throw new FormatException("base64url decode failed: " + ex.Message, ex);
        }
    }

    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        // Strip standard base64 padding and translate the URL-safe alphabet.
        int trim = 0;
        while (trim < b64.Length && b64[b64.Length - 1 - trim] == '=') trim++;
        if (trim > 0) b64 = b64.Substring(0, b64.Length - trim);
        return b64.Replace('+', '-').Replace('/', '_');
    }
}
