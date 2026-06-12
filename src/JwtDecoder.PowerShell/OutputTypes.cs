using System.Management.Automation;
using JwtDecoder.Core;

namespace JwtDecoder.PowerShell;

/// <summary>
/// PowerShell-friendly view of a decoded JSON Web Token. The <see cref="Header"/> and
/// <see cref="Payload"/> properties are <see cref="PSObject"/> instances with note properties
/// for each claim, so users can write <c>$jwt.Payload.sub</c>.
/// </summary>
public sealed class DecodedJsonWebToken
{
    public string Algorithm { get; init; } = string.Empty;
    public string? Type { get; init; }

    public PSObject Header { get; init; } = new PSObject();
    public PSObject Payload { get; init; } = new PSObject();

    public DateTimeOffset? IssuedAt { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>VALID / EXPIRED / NOT YET VALID / UNKNOWN.</summary>
    public string TimeStatus { get; init; } = "UNKNOWN";

    // Populated only when -Detailed was passed.
    public string? HeaderSegment { get; init; }
    public string? PayloadSegment { get; init; }
    public string? SignatureSegment { get; init; }
    public string? SignatureHex { get; init; }

    // Unix-seconds range supported by DateTimeOffset.FromUnixTimeSeconds.
    private const long MinUnixSeconds = -62135596800L;
    private const long MaxUnixSeconds =  253402300799L;

    internal static DecodedJsonWebToken FromJwt(Jwt jwt, bool detailed)
    {
        DateTimeOffset? iat = ToDateTimeOffset(jwt, "iat");
        DateTimeOffset? nbf = ToDateTimeOffset(jwt, "nbf");
        DateTimeOffset? exp = ToDateTimeOffset(jwt, "exp");

        var now = DateTimeOffset.UtcNow;
        string status;
        if (nbf.HasValue && now < nbf.Value) status = "NOT YET VALID";
        else if (exp.HasValue && now > exp.Value) status = "EXPIRED";
        else if (iat.HasValue || nbf.HasValue || exp.HasValue) status = "VALID";
        else status = "UNKNOWN";

        return new DecodedJsonWebToken
        {
            Algorithm = jwt.Algorithm,
            Type = jwt.Type,
            Header = PsConversion.ToPSObject(jwt.Header.RootElement),
            Payload = PsConversion.ToPSObject(jwt.Payload.RootElement),
            IssuedAt = iat,
            NotBefore = nbf,
            Expiration = exp,
            TimeStatus = status,
            HeaderSegment    = detailed ? jwt.HeaderSegment    : null,
            PayloadSegment   = detailed ? jwt.PayloadSegment   : null,
            SignatureSegment = detailed ? jwt.SignatureSegment : null,
            SignatureHex     = detailed && jwt.SignatureBytes.Length > 0
                ? Convert.ToHexString(jwt.SignatureBytes).ToLowerInvariant()
                : (detailed ? string.Empty : null),
        };
    }

    private static DateTimeOffset? ToDateTimeOffset(Jwt jwt, string claim)
    {
        if (!Jwt.TryGetUnixSeconds(jwt.Payload.RootElement, claim, out long seconds))
            return null;
        if (seconds < MinUnixSeconds || seconds > MaxUnixSeconds)
            return null;
        return DateTimeOffset.FromUnixTimeSeconds(seconds);
    }
}

/// <summary>
/// Outcome of a signature verification attempt. <see cref="IsValid"/> is <c>true</c> iff the
/// cryptographic check succeeded with the supplied key and the JWT's algorithm.
/// </summary>
public sealed class JsonWebTokenVerification
{
    public bool IsValid { get; init; }
    public string Algorithm { get; init; } = string.Empty;
    public string? Error { get; init; }

    internal static JsonWebTokenVerification FromOutcome(VerifyOutcome outcome) =>
        new()
        {
            IsValid = outcome.Verified,
            Algorithm = outcome.Algorithm,
            Error = outcome.Error,
        };
}
