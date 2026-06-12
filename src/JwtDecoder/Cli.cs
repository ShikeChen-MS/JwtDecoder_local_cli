using System.Reflection;

namespace JwtDecoder;

internal sealed class CliOptions
{
    public string? Token { get; init; }
    public string? TokenFile { get; init; }
    public bool Detailed { get; init; }
    public bool Verify { get; init; }
    public string? KeyFile { get; init; }
    public bool Help { get; init; }
    public bool Version { get; init; }
}

internal static class Cli
{
    public static string VersionString =>
        typeof(Cli).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(Cli).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    public static (CliOptions? options, string? error) Parse(string[] args)
    {
        string? token = null;
        string? tokenFile = null;
        bool detailed = false;
        bool verify = false;
        string? keyFile = null;
        bool help = false;
        bool version = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-h":
                case "--help":
                    help = true;
                    break;
                case "-v":
                case "--version":
                    version = true;
                    break;
                case "-d":
                case "--detailed":
                    detailed = true;
                    break;
                case "--verify":
                    verify = true;
                    break;
                case "--file":
                    if (++i >= args.Length) return (null, "Error: --file requires a path.");
                    if (tokenFile is not null) return (null, "Error: --file specified more than once.");
                    tokenFile = args[i];
                    break;
                case "--key-file":
                    if (++i >= args.Length) return (null, "Error: --key-file requires a path.");
                    if (keyFile is not null) return (null, "Error: --key-file specified more than once.");
                    keyFile = args[i];
                    break;
                default:
                    if (a.StartsWith('-'))
                        return (null, $"Error: unknown option '{a}'. Use --help for usage.");
                    if (token is not null)
                        return (null, "Error: more than one token argument supplied.");
                    token = a;
                    break;
            }
        }

        if (token is not null && tokenFile is not null)
            return (null, "Error: provide either a positional token OR --file, not both.");
        if (verify && keyFile is null)
            return (null, "Error: --verify requires --key-file <path>.");
        if (keyFile is not null && !verify)
            return (null, "Error: --key-file is only meaningful with --verify.");

        return (new CliOptions
        {
            Token = token,
            TokenFile = tokenFile,
            Detailed = detailed,
            Verify = verify,
            KeyFile = keyFile,
            Help = help,
            Version = version,
        }, null);
    }

    public static void PrintHelp(TextWriter w)
    {
        w.WriteLine("jwtdecode \u2014 offline JSON Web Token decoder");
        w.WriteLine();
        w.WriteLine("USAGE:");
        w.WriteLine("  jwtdecode <token>                          Decode a JWT (simplified output).");
        w.WriteLine("  jwtdecode --file <path>                    Read the token from a file.");
        w.WriteLine("  <pipe> | jwtdecode                         Read the token from stdin.");
        w.WriteLine();
        w.WriteLine("OPTIONS:");
        w.WriteLine("  -d, --detailed                             Also print raw segments and signature bytes.");
        w.WriteLine("      --verify                               Verify the signature (requires --key-file).");
        w.WriteLine("      --key-file <path>                      Path to the key file (HMAC raw secret or PEM PUBLIC key).");
        w.WriteLine("      --file <path>                          Read the JWT from <path>.");
        w.WriteLine("  -h, --help                                 Show this help.");
        w.WriteLine("  -v, --version                              Show version.");
        w.WriteLine();
        w.WriteLine("KEY FILE FORMAT (with --verify):");
        w.WriteLine("  HS256/HS384/HS512 -> raw secret bytes (a single trailing newline is stripped).");
        w.WriteLine("                       Refused if the file looks like PEM (algorithm-confusion guard).");
        w.WriteLine("  RS*/PS*           -> PEM-encoded RSA PUBLIC key. Private keys are REFUSED.");
        w.WriteLine("  ES*               -> PEM-encoded EC PUBLIC key matching the JOSE curve binding:");
        w.WriteLine("                         ES256 \u2194 P-256,  ES384 \u2194 P-384,  ES512 \u2194 P-521.");
        w.WriteLine();
        w.WriteLine("EXIT CODES:");
        w.WriteLine("  0  Success.");
        w.WriteLine("  1  Unexpected error.");
        w.WriteLine("  2  Invalid input (bad token, bad arguments, missing/oversized/unreadable file).");
        w.WriteLine("  3  Signature verification failed.");
        w.WriteLine();
        w.WriteLine("SECURITY:");
        w.WriteLine("  This tool never makes network calls. All decoding and verification is local.");
        w.WriteLine("  Sensitive buffers (HMAC secret, decoded segments, signing input) are zeroed");
        w.WriteLine("  in memory before release, and an aggressive GC pass is forced before exit.");
        w.WriteLine("  Algorithm-confusion attacks (PEM-as-HMAC-secret) are explicitly rejected.");
        w.WriteLine("  Tokens passed via positional argument may persist in shell history; prefer --file or stdin.");
    }
}
