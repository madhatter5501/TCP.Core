using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Creates and checks the handshake signatures that prove the server holds its certificate's private key.
/// </summary>
/// <remarks>
/// <para>
/// The Diffie-Hellman exchange alone is anonymous: a man in the middle could run one exchange with each side. The
/// server therefore signs something only this handshake could produce. TLS 1.2 signs the two hello randoms plus
/// its ECDHE parameters (RFC 8422 5.4); TLS 1.3 signs the hash of the whole transcript so far (RFC 8446 4.4.3),
/// prefixed so the signature cannot be replayed in another context:
/// <code>
/// 64 bytes of 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || Transcript-Hash(ClientHello..Certificate)
/// </code>
/// The leading spaces defeat an old attack where a TLS 1.2 signature's randoms were chosen to look like a prefix.
/// </para>
/// <para>
/// TLS encodes ECDSA signatures as the DER SEQUENCE { r INTEGER, s INTEGER } (RFC 3279), not the fixed-width r||s
/// that .NET produces by default.
/// </para>
/// </remarks>
internal static class TlsSignatures
{
    private const byte ContextPadByte = 0x20;
    private const int ContextPadLength = 64;
    private const string ServerContext = "TLS 1.3, server CertificateVerify";
    private const string ClientContext = "TLS 1.3, client CertificateVerify";
    private const int P256KeySize = 256;
    private const int P384KeySize = 384;
    private const int P521KeySize = 521;

    /// <summary>Schemes a client offers, strongest-first within each family, ECDSA first.</summary>
    public static IReadOnlyList<TlsSignatureScheme> DefaultOffered { get; } =
    [
        TlsSignatureScheme.EcdsaSecp256r1Sha256, 
        TlsSignatureScheme.EcdsaSecp384r1Sha384, 
        TlsSignatureScheme.EcdsaSecp521r1Sha512,
        TlsSignatureScheme.RsaPssRsaeSha256, 
        TlsSignatureScheme.RsaPssRsaeSha384, 
        TlsSignatureScheme.RsaPssRsaeSha512,
        TlsSignatureScheme.RsaPkcs1Sha256, 
        TlsSignatureScheme.RsaPkcs1Sha384, 
        TlsSignatureScheme.RsaPkcs1Sha512,
    ];

    /// <summary>RFC 8446 4.4.3: the bytes a TLS 1.3 CertificateVerify signs.</summary>
    public static byte[] Tls13SignedContent(bool server, byte[] transcriptHash)
    {
        var context = System.Text.Encoding.ASCII.GetBytes(server ? ServerContext : ClientContext);
        var content = new byte[ContextPadLength + context.Length + 1 + transcriptHash.Length];
        content.AsSpan(0, ContextPadLength).Fill(ContextPadByte);
        context.CopyTo(content, ContextPadLength);
        transcriptHash.CopyTo(content, ContextPadLength + context.Length + 1); // The 0x00 separator is already zero.
        return content;
    }

    /// <summary>The schemes a private key can produce under <paramref name="version"/>, best first.</summary>
    public static IReadOnlyList<TlsSignatureScheme> SchemesFor(AsymmetricAlgorithm key, TlsVersion version) => key switch
    {
        // TLS 1.3 binds each ECDSA scheme to one curve; TLS 1.2 treats the scheme as just (hash, ECDSA).
        ECDsa ecdsa when version == TlsVersion.Tls13 => [CurveScheme(ecdsa.KeySize)],
        ECDsa ecdsa => [CurveScheme(ecdsa.KeySize), .. DefaultOffered.Where(s => Family(s) == ServerAuthentication.Ecdsa && s != CurveScheme(ecdsa.KeySize))],
        RSA when version == TlsVersion.Tls13 => [.. DefaultOffered.Where(IsRsaPss)],
        RSA => [.. DefaultOffered.Where(s => Family(s) == ServerAuthentication.Rsa)],
        _ => [],
    };

    /// <summary>Which kind of key produces <paramref name="scheme"/>.</summary>
    public static ServerAuthentication Family(TlsSignatureScheme scheme) => scheme switch
    {
        TlsSignatureScheme.EcdsaSecp256r1Sha256 or TlsSignatureScheme.EcdsaSecp384r1Sha384 or TlsSignatureScheme.EcdsaSecp521r1Sha512 => ServerAuthentication.Ecdsa,
        _ when IsRsaPss(scheme) || IsRsaPkcs1(scheme) => ServerAuthentication.Rsa,
        _ => ServerAuthentication.Any,
    };

    /// <summary>Signs <paramref name="data"/> with <paramref name="key"/> as <paramref name="scheme"/> requires.</summary>
    public static byte[] Sign(TlsSignatureScheme scheme, AsymmetricAlgorithm key, byte[] data) => key switch
    {
        ECDsa ecdsa => ecdsa.SignData(data, HashOf(scheme), DSASignatureFormat.Rfc3279DerSequence),
        RSA rsa => rsa.SignData(data, HashOf(scheme), IsRsaPss(scheme) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
        _ => throw new NotSupportedException(TlsMessages.UnsupportedKey),
    };

    /// <summary>
    /// True when <paramref name="signature"/> is a valid <paramref name="scheme"/> signature of <paramref name="data"/>
    /// by <paramref name="certificate"/>'s key, and the scheme is allowed in <paramref name="version"/>.
    /// </summary>
    public static bool Verify(TlsSignatureScheme scheme, X509Certificate2 certificate, byte[] data, byte[] signature, TlsVersion version)
    {
        try
        {
            switch (Family(scheme))
            {
                case ServerAuthentication.Ecdsa:
                    using (var ecdsa = certificate.GetECDsaPublicKey())
                    {
                        if (ecdsa is null) return false;
                        if (version == TlsVersion.Tls13 && CurveScheme(ecdsa.KeySize) != scheme) return false;
                        return ecdsa.VerifyData(data, signature, HashOf(scheme), DSASignatureFormat.Rfc3279DerSequence);
                    }
                case ServerAuthentication.Rsa:
                    if (version == TlsVersion.Tls13 && !IsRsaPss(scheme)) return false; // RFC 8446 4.4.3
                    using (var rsa = certificate.GetRSAPublicKey())
                        return rsa is not null && rsa.VerifyData(data, signature, HashOf(scheme),
                            IsRsaPss(scheme) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>The hash a scheme signs with.</summary>
    public static HashAlgorithmName HashOf(TlsSignatureScheme scheme) => scheme switch
    {
        TlsSignatureScheme.RsaPkcs1Sha256 or TlsSignatureScheme.EcdsaSecp256r1Sha256 or TlsSignatureScheme.RsaPssRsaeSha256 => HashAlgorithmName.SHA256,
        TlsSignatureScheme.RsaPkcs1Sha384 or TlsSignatureScheme.EcdsaSecp384r1Sha384 or TlsSignatureScheme.RsaPssRsaeSha384 => HashAlgorithmName.SHA384,
        TlsSignatureScheme.RsaPkcs1Sha512 or TlsSignatureScheme.EcdsaSecp521r1Sha512 or TlsSignatureScheme.RsaPssRsaeSha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException(TlsMessages.UnsupportedSignatureScheme),
    };

    /// <summary>The TLS 1.3 ECDSA scheme for a curve of <paramref name="keySize"/> bits.</summary>
    private static TlsSignatureScheme CurveScheme(int keySize) => keySize switch
    {
        P256KeySize => TlsSignatureScheme.EcdsaSecp256r1Sha256,
        P384KeySize => TlsSignatureScheme.EcdsaSecp384r1Sha384,
        P521KeySize => TlsSignatureScheme.EcdsaSecp521r1Sha512,
        _ => throw new NotSupportedException(TlsMessages.UnsupportedKey),
    };

    private static bool IsRsaPss(TlsSignatureScheme scheme) =>
        scheme is TlsSignatureScheme.RsaPssRsaeSha256 or TlsSignatureScheme.RsaPssRsaeSha384 or TlsSignatureScheme.RsaPssRsaeSha512;

    private static bool IsRsaPkcs1(TlsSignatureScheme scheme) =>
        scheme is TlsSignatureScheme.RsaPkcs1Sha256 or TlsSignatureScheme.RsaPkcs1Sha384 or TlsSignatureScheme.RsaPkcs1Sha512;
}
