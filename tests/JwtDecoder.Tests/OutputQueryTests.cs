using System.Text;
using JwtDecoder;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Tests;

/// <summary>
/// Tests for <see cref="Output.WriteQueryResults"/> that guard against the
/// security invariants exercised by the CLI: terminal-injection refusal under
/// <c>--raw</c>, atomic stdout commit when any path is missing, and JSON-form
/// safety when control characters appear in claim values.
/// </summary>
public class OutputQueryTests
{
    // payload (decoded) =
    //   { "sub":"alice",
    //     "evil":"\u001b[31mBOO\u001b[0m",   // ESC bytes via JSON escape
    //     "name":"John\nDoe",                 // LF via JSON escape
    //     "roles":["admin","user"],
    //     "active":true,
    //     "null_value":null }
    //
    // The JSON sent into the JWT uses \uXXXX / \n escapes (per RFC 8259), so the bytes on
    // the wire are 7-bit safe. Jwt.Parse decodes them into actual ESC / LF characters in
    // the resulting JsonElement string values — exactly the adversarial shape we want to
    // exercise the terminal-injection guard against.
    private static Jwt BuildTestJwt()
    {
        string headerJson  = "{\"alg\":\"HS256\"}";
        string payloadJson =
            "{\"sub\":\"alice\"," +
            "\"evil\":\"\\u001b[31mBOO\\u001b[0m\"," +
            "\"name\":\"John\\nDoe\"," +
            "\"roles\":[\"admin\",\"user\"]," +
            "\"active\":true," +
            "\"null_value\":null}";
        string header  = ToBase64Url(Encoding.UTF8.GetBytes(headerJson));
        string payload = ToBase64Url(Encoding.UTF8.GetBytes(payloadJson));
        return Jwt.Parse($"{header}.{payload}.sig");
    }

    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // -----------------------------------------------------------------
    // Default JSON output is terminal-safe even for control-character claims
    // -----------------------------------------------------------------

    [Fact]
    public void Default_output_escapes_C0_control_chars_in_string_values()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        int idx = Output.WriteQueryResults(sw, jwt, "payload.evil", raw: false, out string missing);
        Assert.Equal(-1, idx);
        Assert.Equal(string.Empty, missing);

        // ESC byte (0x1B) MUST NOT appear verbatim; it must be a JSON \u001b escape.
        string captured = sw.ToString();
        Assert.DoesNotContain('\u001b', captured);
        Assert.Contains("\\u001b", captured, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Default_output_escapes_newline_in_string_values()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        _ = Output.WriteQueryResults(sw, jwt, "payload.name", raw: false, out _);
        // The literal LF byte (0x0A) inside the claim value must be JSON-escaped, not passed
        // through. The only LF in the captured output is the trailing WriteLine terminator.
        string captured = sw.ToString();
        Assert.Contains("\\n", captured);
        Assert.Equal(-1, captured.TrimEnd('\r', '\n').IndexOf('\n'));
    }

    // -----------------------------------------------------------------
    // --raw refuses any string value containing C0/DEL/C1 control characters
    // -----------------------------------------------------------------

    [Fact]
    public void Raw_mode_refuses_string_value_with_C0_control_char_and_writes_nothing()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        var ex = Assert.Throws<InvalidDataException>(
            () => Output.WriteQueryResults(sw, jwt, "payload.evil", raw: true, out _));
        Assert.Contains("control character", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--raw", ex.Message);
        // Atomic-commit invariant: nothing on the writer.
        Assert.Equal(string.Empty, sw.ToString());
    }

    [Fact]
    public void Raw_mode_refuses_string_value_with_embedded_newline_and_writes_nothing()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        Assert.Throws<InvalidDataException>(
            () => Output.WriteQueryResults(sw, jwt, "payload.name", raw: true, out _));
        Assert.Equal(string.Empty, sw.ToString());
    }

    [Fact]
    public void Raw_mode_emits_clean_string_value_unwrapped()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        int idx = Output.WriteQueryResults(sw, jwt, "payload.sub", raw: true, out _);
        Assert.Equal(-1, idx);
        Assert.Equal("alice" + Environment.NewLine, sw.ToString());
    }

    [Theory]
    [InlineData("payload.active",     "true")]   // bool fine
    [InlineData("payload.null_value", "null")]   // JSON null literal
    [InlineData("payload.roles",      "[\"admin\",\"user\"]")]  // array (compact JSON via Utf8JsonWriter)
    public void Raw_mode_passes_non_string_kinds_through_safely(string path, string expected)
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        int idx = Output.WriteQueryResults(sw, jwt, path, raw: true, out _);
        Assert.Equal(-1, idx);
        Assert.Equal(expected + Environment.NewLine, sw.ToString());
    }

    // -----------------------------------------------------------------
    // Multi-path atomic commit on missing paths
    // -----------------------------------------------------------------

    [Fact]
    public void Multi_path_with_missing_middle_path_writes_nothing_and_returns_index()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        int idx = Output.WriteQueryResults(
            sw, jwt, "payload.sub,payload.missing,payload.active", raw: true, out string missing);
        Assert.Equal(1, idx);
        Assert.Equal("payload.missing", missing);
        // Critical: the first path resolved but its value must NOT have been committed,
        // otherwise a script that ignores the non-zero exit code consumes partial data.
        Assert.Equal(string.Empty, sw.ToString());
    }

    [Fact]
    public void Multi_path_all_present_writes_all_in_order()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        int idx = Output.WriteQueryResults(
            sw, jwt, "payload.sub,payload.active,payload.null_value", raw: false, out string missing);
        Assert.Equal(-1, idx);
        Assert.Equal(string.Empty, missing);
        string[] lines = sw.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(new[] { "\"alice\"", "true", "null" }, lines);
    }

    [Fact]
    public void Multi_path_atomic_commit_also_holds_when_late_path_triggers_raw_refusal()
    {
        using var jwt = BuildTestJwt();
        using var sw  = new StringWriter();
        // First two paths would format cleanly under --raw, but the third must trigger the
        // control-character refusal. Nothing on stdout, even though prefix paths were OK.
        Assert.Throws<InvalidDataException>(() =>
            Output.WriteQueryResults(sw, jwt, "payload.sub,payload.active,payload.evil", raw: true, out _));
        Assert.Equal(string.Empty, sw.ToString());
    }
}
