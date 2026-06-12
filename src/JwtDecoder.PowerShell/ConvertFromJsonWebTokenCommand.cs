using System.Management.Automation;
using JwtDecoder.Core;

namespace JwtDecoder.PowerShell;

/// <summary>
/// <c>ConvertFrom-JsonWebToken</c> — decode a JWT into a <see cref="DecodedJsonWebToken"/>
/// without cryptographic verification.
/// </summary>
/// <remarks>
/// Examples:
/// <code>
///   ConvertFrom-JsonWebToken $token
///   Get-Content token.jwt -Raw | ConvertFrom-JsonWebToken
///   ConvertFrom-JsonWebToken -Path .\token.jwt -Detailed
/// </code>
/// </remarks>
[Cmdlet(VerbsData.ConvertFrom, "JsonWebToken", DefaultParameterSetName = ParamSetToken)]
[OutputType(typeof(DecodedJsonWebToken))]
public sealed class ConvertFromJsonWebTokenCommand : PSCmdlet
{
    private const string ParamSetToken = "Token";
    private const string ParamSetPath  = "Path";

    [Parameter(Position = 0, Mandatory = true,
        ValueFromPipeline = true, ValueFromPipelineByPropertyName = true,
        ParameterSetName = ParamSetToken)]
    [AllowEmptyString]
    public string? Token { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = ParamSetPath)]
    [Alias("File", "FilePath", "PSPath")]
    public string? Path { get; set; }

    [Parameter]
    public SwitchParameter Detailed { get; set; }

    protected override void ProcessRecord()
    {
        string token;
        try
        {
            token = ResolveToken();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            WriteError(new ErrorRecord(ex, "ReadInputFailed", ErrorCategory.OpenError, Path));
            return;
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            WriteError(new ErrorRecord(
                new ArgumentException("No JWT provided."),
                "EmptyToken", ErrorCategory.InvalidArgument, Token));
            return;
        }

        Jwt jwt;
        try { jwt = Jwt.Parse(token); }
        catch (FormatException ex)
        {
            WriteError(new ErrorRecord(ex, "InvalidJwt", ErrorCategory.InvalidData, null));
            return;
        }

        try
        {
            WriteObject(DecodedJsonWebToken.FromJwt(jwt, Detailed.IsPresent));
        }
        finally
        {
            jwt.Dispose();
        }
    }

    private string ResolveToken()
    {
        if (ParameterSetName == ParamSetPath)
        {
            string resolved = GetUnresolvedProviderPathFromPSPath(Path!);
            // Bounded read to match the CLI: refuse oversized inputs.
            return ReadBoundedAllText(resolved, Jwt.MaxTokenChars);
        }
        return Token ?? string.Empty;
    }

    private static string ReadBoundedAllText(string path, int maxChars)
    {
        // Read up to maxChars+1 chars; if we got more, it's too big.
        // Use a StreamReader to handle BOM/encoding consistently.
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sr = new StreamReader(fs);
        char[] buf = new char[Math.Min(maxChars + 1, 64 * 1024)];
        int total = 0;
        var sb = new System.Text.StringBuilder();
        int n;
        while ((n = sr.Read(buf, 0, buf.Length)) > 0)
        {
            if (total + n > maxChars)
                throw new InvalidDataException($"Token file is too large (max {maxChars:N0} chars).");
            sb.Append(buf, 0, n);
            total += n;
        }
        // Best-effort zero of the read buffer.
        Array.Clear(buf, 0, buf.Length);
        return sb.ToString();
    }
}
