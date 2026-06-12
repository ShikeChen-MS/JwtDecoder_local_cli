using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using JwtDecoder.Core;

namespace JwtDecoder.PowerShell;

/// <summary>
/// <c>Test-JsonWebTokenSignature</c> — verify a JWT's signature against a key.
/// </summary>
/// <remarks>
/// Three parameter sets for supplying the key:
/// <list type="bullet">
/// <item><c>-KeyFile &lt;path&gt;</c> — file containing the HMAC secret (raw bytes) or PEM public key. Same rules as the CLI.</item>
/// <item><c>-Secret &lt;SecureString&gt;</c> — HMAC secret as a PowerShell <c>SecureString</c>. The decoded UTF-8 bytes are zeroed after use.</item>
/// <item><c>-PublicKey &lt;RSA|ECDsa&gt;</c> — already-loaded asymmetric public key. Ownership stays with the caller.</item>
/// </list>
/// Returns a <see cref="JsonWebTokenVerification"/> with <c>IsValid</c>, <c>Algorithm</c>, and an optional <c>Error</c>.
/// Verification failure does NOT throw a terminating error — call sites can branch on <c>.IsValid</c>.
/// </remarks>
[Cmdlet(VerbsDiagnostic.Test, "JsonWebTokenSignature", DefaultParameterSetName = ParamSetKeyFile)]
[OutputType(typeof(JsonWebTokenVerification))]
public sealed class TestJsonWebTokenSignatureCommand : PSCmdlet
{
    private const string ParamSetKeyFile   = "KeyFile";
    private const string ParamSetSecret    = "Secret";
    private const string ParamSetPublicKey = "PublicKey";

    [Parameter(Position = 0, Mandatory = true,
        ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string Token { get; set; } = string.Empty;

    [Parameter(Mandatory = true, ParameterSetName = ParamSetKeyFile)]
    [Alias("KeyPath")]
    public string KeyFile { get; set; } = string.Empty;

    [Parameter(Mandatory = true, ParameterSetName = ParamSetSecret)]
    public SecureString? Secret { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = ParamSetPublicKey)]
    public AsymmetricAlgorithm? PublicKey { get; set; }

    protected override void ProcessRecord()
    {
        if (string.IsNullOrWhiteSpace(Token))
        {
            WriteError(new ErrorRecord(
                new ArgumentException("Token is empty."),
                "EmptyToken", ErrorCategory.InvalidArgument, null));
            return;
        }

        Jwt jwt;
        try { jwt = Jwt.Parse(Token); }
        catch (FormatException ex)
        {
            WriteError(new ErrorRecord(ex, "InvalidJwt", ErrorCategory.InvalidData, null));
            return;
        }

        try
        {
            KeyMaterial? key;
            try
            {
                key = ResolveKey(jwt.Algorithm);
            }
            catch (Exception ex) when (ex is FileNotFoundException
                                          or DirectoryNotFoundException
                                          or UnauthorizedAccessException
                                          or IOException
                                          or InvalidDataException
                                          or NotSupportedException
                                          or InvalidOperationException
                                          or ArgumentException)
            {
                WriteError(new ErrorRecord(ex, "KeyLoadFailed", ErrorCategory.InvalidArgument, null));
                return;
            }

            try
            {
                VerifyOutcome outcome = JwtVerifier.Verify(jwt, key);
                WriteObject(JsonWebTokenVerification.FromOutcome(outcome));
            }
            finally
            {
                key?.Dispose();
            }
        }
        finally
        {
            jwt.Dispose();
        }
    }

    private KeyMaterial? ResolveKey(string algorithm)
    {
        switch (ParameterSetName)
        {
            case ParamSetKeyFile:
                {
                    string resolved = GetUnresolvedProviderPathFromPSPath(KeyFile);
                    return KeyLoader.Load(resolved, algorithm);
                }

            case ParamSetSecret:
                {
                    if (Secret is null) throw new ArgumentNullException(nameof(Secret));
                    byte[] bytes = SecureStringToUtf8Bytes(Secret);
                    try
                    {
                        return KeyLoader.CreateHmacFromBytes(bytes, algorithm);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(bytes);
                    }
                }

            case ParamSetPublicKey:
                {
                    if (PublicKey is null) throw new ArgumentNullException(nameof(PublicKey));
                    return PublicKey switch
                    {
                        RSA rsa     => KeyLoader.CreateRsaShared(rsa, algorithm),
                        ECDsa ec    => KeyLoader.CreateEcdsaShared(ec, algorithm),
                        _ => throw new InvalidOperationException(
                            $"PublicKey must be an RSA or ECDsa instance; got {PublicKey.GetType().Name}."),
                    };
                }

            default:
                throw new InvalidOperationException($"Unknown parameter set: {ParameterSetName}");
        }
    }

    /// <summary>
    /// Decode a <see cref="SecureString"/> into a UTF-8 byte array.
    /// The intermediate BSTR and char buffers are zeroed before return.
    /// The caller is responsible for zeroing the returned byte[] when done.
    /// </summary>
    private static byte[] SecureStringToUtf8Bytes(SecureString secret)
    {
        if (secret.Length == 0) return Array.Empty<byte>();

        IntPtr bstr = IntPtr.Zero;
        char[]? chars = null;
        try
        {
            bstr = Marshal.SecureStringToBSTR(secret);
            chars = new char[secret.Length];
            Marshal.Copy(bstr, chars, 0, secret.Length);

            int byteCount = Encoding.UTF8.GetByteCount(chars);
            byte[] bytes = new byte[byteCount];
            Encoding.UTF8.GetBytes(chars, 0, chars.Length, bytes, 0);
            return bytes;
        }
        finally
        {
            if (chars is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
            if (bstr != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstr);
        }
    }
}
