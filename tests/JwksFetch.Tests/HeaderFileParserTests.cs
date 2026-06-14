using JwtDecoder.JwksFetcher;
using Xunit;

namespace JwksFetch.Tests;

public class HeaderFileParserTests
{
    [Fact]
    public void Parses_simple_two_headers()
    {
        var result = HeaderFileParser.Parse("X-Foo: bar\nX-Other: baz");
        Assert.Equal(2, result.Count);
        Assert.Equal("X-Foo", result[0].Name);
        Assert.Equal("bar", result[0].Value);
        Assert.Equal("X-Other", result[1].Name);
        Assert.Equal("baz", result[1].Value);
    }

    [Fact]
    public void Skips_blank_lines_and_comments()
    {
        var result = HeaderFileParser.Parse(
            "\n# leading comment\n\nX-Foo: bar\n  # indented comment\n");
        Assert.Single(result);
        Assert.Equal("X-Foo", result[0].Name);
    }

    [Fact]
    public void Strips_whitespace_around_value()
    {
        var result = HeaderFileParser.Parse("X-Foo:   spaced value  ");
        Assert.Equal("spaced value  ", result[0].Value); // only leading WS trimmed
    }

    [Fact]
    public void Handles_crlf_line_endings()
    {
        var result = HeaderFileParser.Parse("X-A: 1\r\nX-B: 2\r\n");
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void Missing_colon_is_error()
    {
        Assert.Throws<InvalidDataException>(() => HeaderFileParser.Parse("X-Foo bar"));
    }

    [Fact]
    public void Empty_name_is_error()
    {
        Assert.Throws<InvalidDataException>(() => HeaderFileParser.Parse(":   bar"));
    }

    [Theory]
    [InlineData("Bad Name: x")]    // space in name
    [InlineData("Bad@Name: x")]    // @ not in RFC 7230 token
    [InlineData("Bad/Name: x")]    // / not in token
    [InlineData("Bad(Name: x")]
    public void Invalid_token_name_is_error(string line)
    {
        Assert.Throws<InvalidDataException>(() => HeaderFileParser.Parse(line));
    }

    [Theory]
    [InlineData("Host")]
    [InlineData("authorization")] // case-insensitive denylist
    [InlineData("Proxy-Authorization")]
    [InlineData("Cookie")]
    [InlineData("Connection")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Upgrade")]
    [InlineData("Expect")]
    [InlineData("Content-Length")]
    [InlineData("TE")]
    [InlineData("Trailer")]
    public void Denylist_header_is_refused(string name)
    {
        var ex = Assert.Throws<InvalidDataException>(() =>
            HeaderFileParser.Parse($"{name}: value"));
        Assert.Contains("denylist", ex.Message);
    }

    [Theory]
    [InlineData("X-Foo: ev\0il")]
    [InlineData("X-Foo: ev\nil")] // embedded LF
    public void Forbidden_char_in_value_is_error(string line)
    {
        // Note: an embedded CR by itself would be parsed as a line terminator by the splitter.
        Assert.Throws<InvalidDataException>(() => HeaderFileParser.Parse(line));
    }

    [Fact]
    public void Duplicate_name_case_insensitive_is_error()
    {
        Assert.Throws<InvalidDataException>(() =>
            HeaderFileParser.Parse("X-Foo: a\nx-foo: b"));
    }

    [Fact]
    public void ParseFile_missing_path_throws_FileNotFound()
    {
        string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Assert.Throws<FileNotFoundException>(() => HeaderFileParser.ParseFile(path));
    }

    [Fact]
    public void ParseFile_oversized_is_refused()
    {
        string path = System.IO.Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, new byte[HeaderFileParser.MaxHeaderFileBytes + 1]);
            Assert.Throws<InvalidDataException>(() => HeaderFileParser.ParseFile(path));
        }
        finally { File.Delete(path); }
    }
}
