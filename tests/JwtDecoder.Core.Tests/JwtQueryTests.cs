using System.Text.Json;
using JwtDecoder.Core;
using Xunit;

namespace JwtDecoder.Core.Tests;

public class JwtQueryTests
{
    // A small token with a nested object, a nested array, mixed types, and a JSON null.
    // header  = {"alg":"HS256","typ":"JWT"}
    // payload = {"sub":"alice","iat":1700000000,"active":true,"middleName":null,
    //            "roles":["admin","user"],"address":{"city":"Seattle","zip":98101}}
    private const string SampleToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiJhbGljZSIsImlhdCI6MTcwMDAwMDAwMCwiYWN0aXZlIjp0cnVlLCJtaWRkbGVOYW1lIjpudWxsLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwiYWRkcmVzcyI6eyJjaXR5IjoiU2VhdHRsZSIsInppcCI6OTgxMDF9fQ." +
        "sig";

    // -----------------------------------------------------------------
    // TryQuery happy paths
    // -----------------------------------------------------------------

    [Fact]
    public void TryQuery_string_payload_claim_returns_string_element()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.sub", out var el));
        Assert.Equal(JsonValueKind.String, el.ValueKind);
        Assert.Equal("alice", el.GetString());
    }

    [Fact]
    public void TryQuery_header_claim_returns_value()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("header.alg", out var el));
        Assert.Equal("HS256", el.GetString());
    }

    [Fact]
    public void TryQuery_shorthand_resolves_payload_property()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("sub", out var el));
        Assert.Equal("alice", el.GetString());
    }

    [Fact]
    public void TryQuery_array_index_returns_element()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.roles[0]", out var el));
        Assert.Equal("admin", el.GetString());
        Assert.True(jwt.TryQuery("payload.roles[1]", out var el2));
        Assert.Equal("user", el2.GetString());
    }

    [Fact]
    public void TryQuery_nested_object_walk()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.address.city", out var el));
        Assert.Equal("Seattle", el.GetString());
    }

    [Fact]
    public void TryQuery_bare_scope_returns_whole_object()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload", out var el));
        Assert.Equal(JsonValueKind.Object, el.ValueKind);
        Assert.Equal("alice", el.GetProperty("sub").GetString());
    }

    [Fact]
    public void TryQuery_json_null_value_is_a_successful_match()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.middleName", out var el));
        Assert.Equal(JsonValueKind.Null, el.ValueKind);
    }

    [Fact]
    public void TryQuery_number_value_is_returned_as_number_kind()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.iat", out var el));
        Assert.Equal(JsonValueKind.Number, el.ValueKind);
        Assert.Equal(1700000000L, el.GetInt64());
    }

    [Fact]
    public void TryQuery_boolean_value_is_returned_as_true_or_false_kind()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.active", out var el));
        Assert.Equal(JsonValueKind.True, el.ValueKind);
    }

    // -----------------------------------------------------------------
    // TryQuery sad paths
    // -----------------------------------------------------------------

    [Fact]
    public void TryQuery_missing_property_returns_false()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.False(jwt.TryQuery("payload.doesnotexist", out _));
    }

    [Fact]
    public void TryQuery_out_of_bounds_index_returns_false()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.False(jwt.TryQuery("payload.roles[99]", out _));
    }

    [Fact]
    public void TryQuery_property_access_on_non_object_returns_false()
    {
        using var jwt = Jwt.Parse(SampleToken);
        // roles is an array; ".foo" on it is a type mismatch.
        Assert.False(jwt.TryQuery("payload.roles.foo", out _));
    }

    [Fact]
    public void TryQuery_index_into_non_array_returns_false()
    {
        using var jwt = Jwt.Parse(SampleToken);
        // sub is a string; "[0]" on it is a type mismatch.
        Assert.False(jwt.TryQuery("payload.sub[0]", out _));
    }

    [Fact]
    public void TryQuery_index_into_object_property_returns_false()
    {
        using var jwt = Jwt.Parse(SampleToken);
        // address is an object; "[0]" on it is a type mismatch (and runs through to
        // TryQuery as a not-found rather than a parse error, because the bracket follows
        // a property segment — only the explicit scope root rejects [N] at parse time).
        Assert.False(jwt.TryQuery("payload.address[0]", out _));
    }

    [Fact]
    public void TryQuery_invalid_syntax_throws()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.Throws<FormatException>(() => jwt.TryQuery("payload.bad[", out _));
    }

    [Fact]
    public void TryQuery_null_path_throws()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.Throws<ArgumentNullException>(() => jwt.TryQuery(null!, out _));
    }

    // -----------------------------------------------------------------
    // Query (nullable wrapper)
    // -----------------------------------------------------------------

    [Fact]
    public void Query_returns_element_for_present_path()
    {
        using var jwt = Jwt.Parse(SampleToken);
        var el = jwt.Query("payload.sub");
        Assert.NotNull(el);
        Assert.Equal("alice", el!.Value.GetString());
    }

    [Fact]
    public void Query_returns_null_for_missing_path()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.Null(jwt.Query("payload.doesnotexist"));
    }

    [Fact]
    public void Query_static_overload_resolves_against_supplied_jwt()
    {
        using var jwt = Jwt.Parse(SampleToken);
        var el = JwtQuery.Query(jwt, "header.alg");
        Assert.NotNull(el);
        Assert.Equal("HS256", el!.Value.GetString());
    }

    // -----------------------------------------------------------------
    // FormatJson / FormatRaw
    // -----------------------------------------------------------------

    [Fact]
    public void FormatJson_quotes_string_values_and_preserves_escapes()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.sub", out var el));
        Assert.Equal("\"alice\"", JwtQuery.FormatJson(el));
    }

    [Fact]
    public void FormatJson_emits_compact_object_with_no_indentation()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.address", out var el));
        string s = JwtQuery.FormatJson(el);
        Assert.DoesNotContain("\n", s);
        Assert.DoesNotContain("  ", s);
        Assert.Contains("\"city\":\"Seattle\"", s);
        Assert.Contains("\"zip\":98101", s);
    }

    [Fact]
    public void FormatJson_emits_compact_array()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.roles", out var el));
        Assert.Equal("[\"admin\",\"user\"]", JwtQuery.FormatJson(el));
    }

    [Fact]
    public void FormatJson_emits_number_bool_null_literals()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.iat",        out var iat));
        Assert.True(jwt.TryQuery("payload.active",     out var active));
        Assert.True(jwt.TryQuery("payload.middleName", out var middle));
        Assert.Equal("1700000000", JwtQuery.FormatJson(iat));
        Assert.Equal("true",        JwtQuery.FormatJson(active));
        Assert.Equal("null",        JwtQuery.FormatJson(middle));
    }

    [Fact]
    public void FormatRaw_unwraps_string_values()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.sub", out var el));
        Assert.Equal("alice", JwtQuery.FormatRaw(el));
    }

    [Fact]
    public void FormatRaw_returns_literal_null_for_json_null()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.middleName", out var el));
        Assert.Equal("null", JwtQuery.FormatRaw(el));
    }

    [Fact]
    public void FormatRaw_falls_back_to_json_for_non_scalar_values()
    {
        using var jwt = Jwt.Parse(SampleToken);
        Assert.True(jwt.TryQuery("payload.address", out var addr));
        Assert.True(jwt.TryQuery("payload.roles",   out var roles));
        Assert.True(jwt.TryQuery("payload.iat",     out var iat));
        Assert.Equal(JwtQuery.FormatJson(addr),  JwtQuery.FormatRaw(addr));
        Assert.Equal(JwtQuery.FormatJson(roles), JwtQuery.FormatRaw(roles));
        Assert.Equal(JwtQuery.FormatJson(iat),   JwtQuery.FormatRaw(iat));
    }

    // -----------------------------------------------------------------
    // Argument validation
    // -----------------------------------------------------------------

    [Fact]
    public void TryQuery_null_jwt_throws_argument_null_exception()
    {
        Assert.Throws<ArgumentNullException>(() => JwtQuery.TryQuery(null!, "payload.sub", out _));
    }
}
