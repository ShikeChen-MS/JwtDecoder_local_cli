using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class JwtQueryPathTests
{
    // -----------------------------------------------------------------
    // Happy-path parses
    // -----------------------------------------------------------------

    [Fact]
    public void Parse_explicit_payload_segment_yields_payload_scope_and_single_segment()
    {
        var p = JwtQueryPath.Parse("payload.sub");
        Assert.Equal(JwtScope.Payload, p.Scope);
        Assert.Single(p.Segments);
        Assert.Equal("sub", p.Segments[0].Name);
    }

    [Fact]
    public void Parse_explicit_header_segment_yields_header_scope()
    {
        var p = JwtQueryPath.Parse("header.alg");
        Assert.Equal(JwtScope.Header, p.Scope);
        Assert.Single(p.Segments);
        Assert.Equal("alg", p.Segments[0].Name);
    }

    [Fact]
    public void Parse_bare_payload_yields_no_segments_and_payload_scope()
    {
        var p = JwtQueryPath.Parse("payload");
        Assert.Equal(JwtScope.Payload, p.Scope);
        Assert.Empty(p.Segments);
    }

    [Fact]
    public void Parse_bare_header_yields_no_segments_and_header_scope()
    {
        var p = JwtQueryPath.Parse("header");
        Assert.Equal(JwtScope.Header, p.Scope);
        Assert.Empty(p.Segments);
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("iss")]
    [InlineData("custom_claim")]
    [InlineData("a-b-c")]
    public void Parse_shorthand_treats_first_segment_as_payload_property(string name)
    {
        var p = JwtQueryPath.Parse(name);
        Assert.Equal(JwtScope.Payload, p.Scope);
        Assert.Single(p.Segments);
        Assert.Equal(name, p.Segments[0].Name);
    }

    [Fact]
    public void Parse_array_index_after_property_yields_index_segment()
    {
        var p = JwtQueryPath.Parse("payload.roles[0]");
        Assert.Equal(2, p.Segments.Count);
        Assert.Equal("roles", p.Segments[0].Name);
        Assert.True(p.Segments[1].IsIndex);
        Assert.Equal(0, p.Segments[1].Index);
    }

    [Fact]
    public void Parse_multiple_array_indices_walk_in_order()
    {
        var p = JwtQueryPath.Parse("payload.matrix[2][7]");
        Assert.Equal(3, p.Segments.Count);
        Assert.Equal("matrix", p.Segments[0].Name);
        Assert.Equal(2, p.Segments[1].Index);
        Assert.Equal(7, p.Segments[2].Index);
    }

    [Fact]
    public void Parse_nested_property_walk()
    {
        var p = JwtQueryPath.Parse("payload.address.city");
        Assert.Equal(2, p.Segments.Count);
        Assert.Equal("address", p.Segments[0].Name);
        Assert.Equal("city",    p.Segments[1].Name);
    }

    [Fact]
    public void Parse_quoted_segment_allows_dots_and_special_characters_in_property_name()
    {
        var p = JwtQueryPath.Parse("payload.\"x5t#S256\"");
        Assert.Equal(JwtScope.Payload, p.Scope);
        Assert.Single(p.Segments);
        Assert.Equal("x5t#S256", p.Segments[0].Name);
    }

    [Fact]
    public void Parse_quoted_segment_with_dot_does_not_split_on_the_dot()
    {
        var p = JwtQueryPath.Parse("payload.\"some.weird.key\"");
        Assert.Single(p.Segments);
        Assert.Equal("some.weird.key", p.Segments[0].Name);
    }

    [Theory]
    [InlineData("payload.\"a\\\"b\"", "a\"b")]
    [InlineData("payload.\"a\\\\b\"", "a\\b")]
    public void Parse_quoted_segment_recognizes_backslash_escapes(string input, string expected)
    {
        var p = JwtQueryPath.Parse(input);
        Assert.Equal(expected, p.Segments[0].Name);
    }

    [Fact]
    public void Parse_payload_as_payload_claim_is_addressable_via_explicit_prefix()
    {
        // The fact that "payload" is the scope name does not preclude a payload claim called
        // "payload" — the user just has to spell out the prefix explicitly.
        var p = JwtQueryPath.Parse("payload.payload");
        Assert.Equal(JwtScope.Payload, p.Scope);
        Assert.Single(p.Segments);
        Assert.Equal("payload", p.Segments[0].Name);
    }

    [Fact]
    public void Parse_preserves_original_text()
    {
        var p = JwtQueryPath.Parse("  payload.sub  ");
        Assert.Equal("payload.sub", p.Original);
    }

    // -----------------------------------------------------------------
    // ParseMany
    // -----------------------------------------------------------------

    [Fact]
    public void ParseMany_splits_on_top_level_commas()
    {
        var paths = JwtQueryPath.ParseMany("payload.sub,header.alg,payload.exp");
        Assert.Equal(3, paths.Count);
        Assert.Equal("sub", paths[0].Segments[0].Name);
        Assert.Equal(JwtScope.Header, paths[1].Scope);
        Assert.Equal("exp", paths[2].Segments[0].Name);
    }

    [Fact]
    public void ParseMany_ignores_commas_inside_quoted_segments()
    {
        var paths = JwtQueryPath.ParseMany("payload.\"a,b\",header.alg");
        Assert.Equal(2, paths.Count);
        Assert.Equal("a,b", paths[0].Segments[0].Name);
        Assert.Equal(JwtScope.Header, paths[1].Scope);
    }

    [Fact]
    public void ParseMany_ignores_commas_inside_array_index_brackets()
    {
        // Indices themselves cannot contain commas, but the bracket-tracking machinery
        // must still ignore them so a future grammar extension is not blocked by a
        // false positive.
        var paths = JwtQueryPath.ParseMany("payload.roles[0],payload.sub");
        Assert.Equal(2, paths.Count);
        Assert.Equal(0,     paths[0].Segments[1].Index);
        Assert.Equal("sub", paths[1].Segments[0].Name);
    }

    [Fact]
    public void ParseMany_trims_whitespace_between_commas()
    {
        var paths = JwtQueryPath.ParseMany(" payload.sub , header.alg ");
        Assert.Equal(2, paths.Count);
        Assert.Equal("sub", paths[0].Segments[0].Name);
        Assert.Equal(JwtScope.Header, paths[1].Scope);
    }

    [Fact]
    public void ParseMany_single_path_returns_one_element()
    {
        var paths = JwtQueryPath.ParseMany("payload.sub");
        Assert.Single(paths);
    }

    // -----------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_rejects_empty_path(string input)
    {
        Assert.Throws<FormatException>(() => JwtQueryPath.Parse(input));
    }

    [Fact]
    public void Parse_rejects_null_input()
    {
        Assert.Throws<ArgumentNullException>(() => JwtQueryPath.Parse(null!));
    }

    [Theory]
    [InlineData("payload.")]                    // trailing dot
    [InlineData("payload..sub")]                // double dot
    [InlineData("payload.bad[")]                // unterminated bracket
    [InlineData("payload.bad[abc]")]            // non-numeric index
    [InlineData("payload.bad[-1]")]             // negative index
    [InlineData("payload.bad[]")]               // empty index
    [InlineData("payload.foo#bar")]             // invalid bare char
    [InlineData("payload.\"unterminated")]      // unterminated quoted segment
    [InlineData("payload.\"\"")]                // empty quoted segment
    [InlineData("payload.\"bad\\x\"")]          // invalid escape sequence
    [InlineData("payload[0]")]                  // explicit scope cannot be array-indexed
    [InlineData("header[3]")]                   // ditto for header scope
    [InlineData("payload[")]                    // explicit scope + unterminated bracket
    public void Parse_rejects_malformed_paths(string input)
    {
        Assert.Throws<FormatException>(() => JwtQueryPath.Parse(input));
    }

    // -----------------------------------------------------------------
    // DoS hardening: oversized inputs and segment explosions
    // -----------------------------------------------------------------

    [Fact]
    public void Parse_rejects_paths_longer_than_MaxQueryChars()
    {
        string huge = "payload." + new string('a', JwtQueryPath.MaxQueryChars);
        var ex = Assert.Throws<FormatException>(() => JwtQueryPath.Parse(huge));
        Assert.Contains("maximum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseMany_rejects_lists_longer_than_MaxQueryChars()
    {
        string huge = new string('a', JwtQueryPath.MaxQueryChars + 1);
        var ex = Assert.Throws<FormatException>(() => JwtQueryPath.ParseMany(huge));
        Assert.Contains("maximum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_rejects_paths_exceeding_MaxSegments()
    {
        // Build "payload.a.a.a..." with MaxSegments + 1 segments.
        var sb = new System.Text.StringBuilder("payload");
        for (int i = 0; i <= JwtQueryPath.MaxSegments; i++) sb.Append(".a");
        var ex = Assert.Throws<FormatException>(() => JwtQueryPath.Parse(sb.ToString()));
        Assert.Contains("segment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MaxQueryChars_is_a_modest_kilobyte_scale_bound()
    {
        // Sanity check that nobody relaxes the cap by an order of magnitude in a future edit.
        Assert.True(JwtQueryPath.MaxQueryChars > 256);
        Assert.True(JwtQueryPath.MaxQueryChars <= 64 * 1024);
    }

    [Theory]
    [InlineData(",payload.sub")]
    [InlineData("payload.sub,")]
    [InlineData("payload.sub,,header.alg")]
    public void ParseMany_rejects_empty_paths_around_commas(string input)
    {
        Assert.Throws<FormatException>(() => JwtQueryPath.ParseMany(input));
    }

    [Fact]
    public void ParseMany_rejects_unterminated_quoted_segment_across_paths()
    {
        Assert.Throws<FormatException>(() => JwtQueryPath.ParseMany("payload.\"abc,header.alg"));
    }
}
