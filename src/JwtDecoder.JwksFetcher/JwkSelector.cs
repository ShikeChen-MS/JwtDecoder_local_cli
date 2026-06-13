namespace JwtDecoder.JwksFetcher;

/// <summary>
/// Selects the single JWK from a parsed JWKS that matches a JWT's
/// <c>kid</c>/<c>alg</c>/curve, refusing on ambiguity or mismatch.
/// </summary>
/// <remarks>
/// Selection rules (see the JWKS companion design plan):
/// <list type="bullet">
/// <item>The JWT's algorithm is required and used to derive the expected
/// key type and (for EC) curve.</item>
/// <item>If a JWK's <c>alg</c> claim is present, it must equal the JWT's alg.</item>
/// <item>If the JWT carries a <c>kid</c>, the selector picks the JWK with that
/// kid (after filtering by kty/alg/curve). If multiple candidates share the
/// kid, the JWKS is rejected as ambiguous.</item>
/// <item>If the JWT has no <c>kid</c>, the selector accepts the unique
/// candidate when exactly one matches; otherwise it refuses.</item>
/// </list>
/// </remarks>
public static class JwkSelector
{
    /// <summary>The outcome of a successful key selection.</summary>
    /// <param name="Selected">The chosen <see cref="JwkRecord"/>.</param>
    /// <param name="Warning">A non-fatal warning to surface to the operator
    /// (e.g., "JWT has no kid, fell back to single matching key").
    /// <c>null</c> when there is nothing to warn about.</param>
    public sealed record SelectionResult(JwkRecord Selected, string? Warning);

    /// <summary>Select one JWK matching the given JWT algorithm and (optional) kid.</summary>
    /// <param name="keys">The parsed JWKS entries.</param>
    /// <param name="jwtAlg">The JWT header's <c>alg</c> (e.g., "RS256").</param>
    /// <param name="jwtKid">The JWT header's <c>kid</c>, or <c>null</c> if absent.</param>
    /// <exception cref="ArgumentNullException">If <paramref name="keys"/> or <paramref name="jwtAlg"/> is null.</exception>
    /// <exception cref="InvalidDataException">If no key matches, multiple keys match, or a JWK's
    /// claimed <c>alg</c> contradicts the JWT.</exception>
    public static SelectionResult Select(IReadOnlyList<JwkRecord> keys, string jwtAlg, string? jwtKid)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(jwtAlg);

        var (expectedKty, expectedCrv) = ExpectedKtyAndCurve(jwtAlg);

        var candidates = new List<JwkRecord>();
        foreach (var k in keys)
        {
            if (!string.Equals(k.Kty, expectedKty, StringComparison.Ordinal)) continue;
            if (expectedCrv is not null && !string.Equals(k.Crv, expectedCrv, StringComparison.Ordinal)) continue;
            if (k.Alg is not null && !string.Equals(k.Alg, jwtAlg, StringComparison.Ordinal)) continue;
            candidates.Add(k);
        }

        if (candidates.Count == 0)
            throw new InvalidDataException(
                $"No JWK in the JWKS matches the JWT's algorithm '{jwtAlg}'" +
                (expectedCrv is not null ? $" (curve {expectedCrv})" : "") +
                ".");

        if (jwtKid is not null)
        {
            var kidMatches = candidates.Where(c => string.Equals(c.Kid, jwtKid, StringComparison.Ordinal)).ToList();
            if (kidMatches.Count == 0)
                throw new InvalidDataException(
                    $"No JWK with kid='{jwtKid}' matches the JWT's algorithm '{jwtAlg}'.");
            if (kidMatches.Count > 1)
                throw new InvalidDataException(
                    $"Multiple JWKs share kid='{jwtKid}' and algorithm '{jwtAlg}'; JWKS is ambiguous.");
            return new SelectionResult(kidMatches[0], Warning: null);
        }

        if (candidates.Count == 1)
            return new SelectionResult(
                candidates[0],
                Warning: $"JWT has no 'kid'; using the single JWK that matches algorithm '{jwtAlg}'.");

        throw new InvalidDataException(
            $"JWT has no 'kid' and the JWKS contains {candidates.Count} keys matching algorithm '{jwtAlg}'. " +
            "Refusing to pick one (ambiguous).");
    }

    /// <summary>Map a JWT <c>alg</c> string to the JWK <c>kty</c> and (for EC) expected <c>crv</c>.</summary>
    private static (string Kty, string? Crv) ExpectedKtyAndCurve(string jwtAlg) => jwtAlg switch
    {
        "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512" => ("RSA", null),
        "ES256" => ("EC", "P-256"),
        "ES384" => ("EC", "P-384"),
        "ES512" => ("EC", "P-521"),
        _ => throw new InvalidDataException(
            $"JWT algorithm '{jwtAlg}' is not supported by JWKS-based selection. " +
            "Supported: RS256/384/512, PS256/384/512, ES256/384/512."),
    };
}
