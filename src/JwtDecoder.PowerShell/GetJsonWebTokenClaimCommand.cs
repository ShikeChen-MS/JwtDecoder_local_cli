using System.Management.Automation;
using JwtDecoder.Core;

namespace JwtDecoder.PowerShell;

/// <summary>
/// <c>Get-JsonWebTokenClaim</c> — return the value(s) at one or more textual query paths
/// against a decoded JWT, without any of the framing produced by
/// <c>ConvertFrom-JsonWebToken</c>.
/// </summary>
/// <remarks>
/// <para>
/// Query paths use dot/bracket notation with an optional <c>header.</c> or <c>payload.</c>
/// scope prefix. Bare names (e.g. <c>sub</c>) default to <c>payload.</c>. Multiple paths may
/// be supplied as a PowerShell string array or as a comma-separated string.
/// </para>
/// <para>Examples:</para>
/// <code>
///   Get-JsonWebTokenClaim $token -Name payload.sub
///   Get-JsonWebTokenClaim $token -Name header.alg, payload.sub
///   Get-JsonWebTokenClaim $token -Name 'payload.roles[0]'
///   Get-JsonWebTokenClaim -Path .\token.jwt -Name 'payload.address.city'
///   Get-Content token.jwt -Raw | Get-JsonWebTokenClaim -Name sub, exp
/// </code>
/// <para>
/// Returned values are typed PowerShell objects (string, long/double, bool, $null,
/// PSObject for nested objects, object[] for arrays) — the same shape produced by the
/// <c>Payload</c> / <c>Header</c> properties of <c>ConvertFrom-JsonWebToken</c>. Missing
/// paths emit a non-terminating error and produce no output for that name.
/// </para>
/// </remarks>
[Cmdlet(VerbsCommon.Get, "JsonWebTokenClaim", DefaultParameterSetName = ParamSetToken)]
[OutputType(typeof(object))]
public sealed class GetJsonWebTokenClaimCommand : PSCmdlet
{
    private const string ParamSetToken = "Token";
    private const string ParamSetPath  = "Path";

    /// <summary>The compact JWS token to query.</summary>
    [Parameter(Position = 0, Mandatory = true,
        ValueFromPipeline = true, ValueFromPipelineByPropertyName = true,
        ParameterSetName = ParamSetToken)]
    [AllowEmptyString]
    public string? Token { get; set; }

    /// <summary>Path to a file containing the JWT.</summary>
    [Parameter(Mandatory = true, ParameterSetName = ParamSetPath)]
    [Alias("File", "FilePath", "PSPath")]
    public string? Path { get; set; }

    /// <summary>
    /// One or more query paths. Each element may itself be a comma-separated list of paths.
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    [Alias("Query")]
    [ValidateNotNullOrEmpty]
    public string[]? Name { get; set; }

    /// <inheritdoc/>
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

        // Parse all paths up-front so a syntax error fails fast before we touch the token.
        var paths = new List<JwtQueryPath>();
        foreach (var item in Name!)
        {
            if (string.IsNullOrWhiteSpace(item))
            {
                WriteError(new ErrorRecord(
                    new ArgumentException("Query path is empty."),
                    "EmptyQueryPath", ErrorCategory.InvalidArgument, item));
                return;
            }
            try
            {
                paths.AddRange(JwtQueryPath.ParseMany(item));
            }
            catch (FormatException ex)
            {
                WriteError(new ErrorRecord(ex, "InvalidQueryPath", ErrorCategory.InvalidArgument, item));
                return;
            }
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
            foreach (var path in paths)
            {
                if (!JwtQuery.TryQuery(jwt, path, out var el))
                {
                    WriteError(new ErrorRecord(
                        new ItemNotFoundException($"Query path '{path.Original}' not found in token."),
                        "QueryPathNotFound", ErrorCategory.ObjectNotFound, path.Original));
                    continue;
                }
                WriteObject(PsConversion.ToValue(el));
            }
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
            return ReadBoundedAllText(resolved, Jwt.MaxTokenChars);
        }
        return Token ?? string.Empty;
    }

    private static string ReadBoundedAllText(string path, int maxChars)
    {
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
        Array.Clear(buf, 0, buf.Length);
        return sb.ToString();
    }
}
