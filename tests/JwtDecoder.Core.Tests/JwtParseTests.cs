using System.Text;
using System.Text.Json;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class JwtParseTests
{
    // header  = {"alg":"HS256","typ":"JWT"}
    // payload = {"sub":"1234567890","name":"John Doe","iat":1516239022}
    private const string ValidToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // -----------------------------------------------------------------
    // Happy paths
    // -----------------------------------------------------------------

    [Fact]
    public void Parse_valid_HS256_token_yields_populated_fields()
    {
        using var jwt = Jwt.Parse(ValidToken);
        Assert.Equal("HS256", jwt.Algorithm);
        Assert.Equal("JWT", jwt.Type);
        Assert.NotEmpty(jwt.HeaderSegment);
        Assert.NotEmpty(jwt.PayloadSegment);
        Assert.NotEmpty(jwt.SignatureSegment);
        Assert.NotEmpty(jwt.HeaderJsonBytes);
        Assert.NotEmpty(jwt.PayloadJsonBytes);
        Assert.NotEmpty(jwt.SignatureBytes);
        Assert.NotEmpty(jwt.SigningInput);

        Assert.Equal("1234567890", jwt.Payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal("John Doe",   jwt.Payload.RootElement.GetProperty("name").GetString());
        Assert.Equal(1516239022L,  jwt.Payload.RootElement.GetProperty("iat").GetInt64());
    }

    [Fact]
    public void Parse_signing_input_equals_header_dot_payload_ascii()
    {
        using var jwt = Jwt.Parse(ValidToken);
        string expected = jwt.HeaderSegment + "." + jwt.PayloadSegment;
        Assert.Equal(expected, Encoding.ASCII.GetString(jwt.SigningInput));
    }

    [Fact]
    public void Parse_strips_Bearer_prefix()
    {
        using var jwt = Jwt.Parse("Bearer " + ValidToken);
        Assert.Equal("HS256", jwt.Algorithm);
    }

    [Theory]
    [InlineData("\"", "\"")]
    [InlineData("'",  "'")]
    public void Parse_strips_surrounding_quotes(string open, string close)
    {
        using var jwt = Jwt.Parse(open + ValidToken + close);
        Assert.Equal("HS256", jwt.Algorithm);
    }

    [Fact]
    public void Parse_strips_leading_and_trailing_whitespace()
    {
        using var jwt = Jwt.Parse("\r\n  " + ValidToken + "  \n");
        Assert.Equal("HS256", jwt.Algorithm);
    }

    [Fact]
    public void Parse_token_with_no_typ_header_yields_null_type()
    {
        // header = {"alg":"HS256"} ; payload = {"sub":"x"}
        string noTyp =
            "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ4In0." +
            "abc";
        using var jwt = Jwt.Parse(noTyp);
        Assert.Equal("HS256", jwt.Algorithm);
        Assert.Null(jwt.Type);
    }

    [Fact]
    public void Parse_token_with_empty_signature_segment_succeeds_with_zero_byte_sig()
    {
        // alg:none-style token (still passes structural parsing; verify is a separate concern).
        // header = {"alg":"none"} ; payload = {"sub":"x"} ; signature = ""
        string algNone =
            "eyJhbGciOiJub25lIn0." +
            "eyJzdWIiOiJ4In0." +
            "";
        using var jwt = Jwt.Parse(algNone);
        Assert.Equal("none", jwt.Algorithm);
        Assert.Empty(jwt.SignatureBytes);
        Assert.Equal(string.Empty, jwt.SignatureSegment);
    }

    // -----------------------------------------------------------------
    // Argument validation
    // -----------------------------------------------------------------

    [Fact]
    public void Parse_null_throws_argument_null()
    {
        Assert.Throws<ArgumentNullException>(() => Jwt.Parse(null!));
    }

    [Fact]
    public void Parse_oversized_token_throws()
    {
        var huge = new string('a', Jwt.MaxTokenChars + 1);
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse(huge));
        Assert.Contains("maximum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // -----------------------------------------------------------------
    // Structural errors
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("only.two")]                                  // 2 segments
    [InlineData("one")]                                       // 1 segment
    [InlineData("a.b.c.d")]                                   // 4 segments
    public void Parse_wrong_segment_count_throws(string input)
    {
        Assert.Throws<FormatException>(() => Jwt.Parse(input));
    }

    [Fact]
    public void Parse_five_segments_is_reported_as_JWE_not_supported()
    {
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse("a.b.c.d.e"));
        Assert.Contains("JWE", ex.Message);
    }

    [Theory]
    [InlineData(".body.sig")]
    [InlineData("header..sig")]
    public void Parse_empty_header_or_payload_segment_throws(string input)
    {
        Assert.Throws<FormatException>(() => Jwt.Parse(input));
    }

    [Fact]
    public void Parse_invalid_base64url_in_header_throws()
    {
        // '!' is not a valid base64url character.
        Assert.Throws<FormatException>(() => Jwt.Parse("!!!.eyJzdWIiOiJ4In0.sig"));
    }

    [Fact]
    public void Parse_non_json_header_throws()
    {
        // base64url of "not json"
        string bad = "bm90IGpzb24=".TrimEnd('=').Replace('+','-').Replace('/','_');
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse($"{bad}.eyJzdWIiOiJ4In0.sig"));
        Assert.Contains("header", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_non_object_header_throws()
    {
        // header = "string"
        string strHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes("\"a string\""))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        Assert.Throws<FormatException>(() => Jwt.Parse($"{strHeader}.eyJzdWIiOiJ4In0.sig"));
    }

    [Fact]
    public void Parse_non_object_payload_throws()
    {
        // payload = [1,2,3]
        string arrPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("[1,2,3]"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        Assert.Throws<FormatException>(() => Jwt.Parse($"eyJhbGciOiJIUzI1NiJ9.{arrPayload}.sig"));
    }

    [Fact]
    public void Parse_missing_alg_header_throws()
    {
        // header = {"typ":"JWT"} ; payload = {"sub":"x"}
        string noAlg =
            "eyJ0eXAiOiJKV1QifQ." +
            "eyJzdWIiOiJ4In0." +
            "sig";
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse(noAlg));
        Assert.Contains("alg", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_non_string_alg_throws()
    {
        // header = {"alg":123}
        string numAlg = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":123}"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        Assert.Throws<FormatException>(() => Jwt.Parse($"{numAlg}.eyJzdWIiOiJ4In0.sig"));
    }

    [Fact]
    public void Parse_empty_alg_throws()
    {
        // header = {"alg":""}
        string emptyAlg = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"\"}"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse($"{emptyAlg}.eyJzdWIiOiJ4In0.sig"));
        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_duplicate_header_keys_throws()
    {
        // header = {"alg":"HS256","alg":"none"} — JSON parsers may accept this, but JWT spec
        // requires unique JOSE parameter names.
        string dup = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"alg\":\"none\"}"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse($"{dup}.eyJzdWIiOiJ4In0.sig"));
        Assert.Contains("duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_duplicate_payload_keys_throws()
    {
        // payload = {"sub":"a","sub":"b"}
        string dup = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"sub\":\"a\",\"sub\":\"b\"}"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        var ex = Assert.Throws<FormatException>(() => Jwt.Parse($"eyJhbGciOiJIUzI1NiJ9.{dup}.sig"));
        Assert.Contains("duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_oversized_decoded_segment_throws()
    {
        // Build a base64url-encoded segment longer than MaxDecodedSegmentBytes (256 KiB).
        // Encoded length > ((256*1024 + 2) / 3) * 4 + 4 triggers the early rejection.
        int oversizedEncoded = ((Jwt.MaxDecodedSegmentBytes + 2) / 3) * 4 + 8;
        string body = new string('A', oversizedEncoded);
        Assert.Throws<FormatException>(() => Jwt.Parse($"eyJhbGciOiJIUzI1NiJ9.{body}.sig"));
    }

    // -----------------------------------------------------------------
    // Lifetime
    // -----------------------------------------------------------------

    [Fact]
    public void Dispose_is_idempotent()
    {
        var jwt = Jwt.Parse(ValidToken);
        jwt.Dispose();
        jwt.Dispose();  // must not throw
    }

    // -----------------------------------------------------------------
    // TryGetUnixSeconds helper
    // -----------------------------------------------------------------

    [Fact]
    public void TryGetUnixSeconds_reads_numeric_claim()
    {
        using var jwt = Jwt.Parse(ValidToken);
        Assert.True(Jwt.TryGetUnixSeconds(jwt.Payload.RootElement, "iat", out long iat));
        Assert.Equal(1516239022L, iat);
    }

    [Fact]
    public void TryGetUnixSeconds_reads_numeric_string_claim()
    {
        // payload = {"exp":"1700000000"}
        string strExp = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"exp\":\"1700000000\"}"))
            .TrimEnd('=').Replace('+','-').Replace('/','_');
        using var jwt = Jwt.Parse($"eyJhbGciOiJIUzI1NiJ9.{strExp}.sig");
        Assert.True(Jwt.TryGetUnixSeconds(jwt.Payload.RootElement, "exp", out long exp));
        Assert.Equal(1700000000L, exp);
    }

    [Fact]
    public void TryGetUnixSeconds_returns_false_for_missing_claim()
    {
        using var jwt = Jwt.Parse(ValidToken);
        Assert.False(Jwt.TryGetUnixSeconds(jwt.Payload.RootElement, "exp", out long exp));
        Assert.Equal(0, exp);
    }

    [Fact]
    public void TryGetUnixSeconds_returns_false_for_non_numeric_value()
    {
        using var jwt = Jwt.Parse(ValidToken);
        Assert.False(Jwt.TryGetUnixSeconds(jwt.Payload.RootElement, "name", out long _));
    }

    [Fact]
    public void TryGetUnixSeconds_returns_false_when_root_is_not_object()
    {
        var doc = JsonDocument.Parse("\"not an object\"");
        Assert.False(Jwt.TryGetUnixSeconds(doc.RootElement, "anything", out long _));
    }
}
