using System.Security.Cryptography;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>Which authenticated encryption algorithm protects records.</summary>
internal enum AeadAlgorithm
{
    /// <summary>AES in Galois/Counter Mode (NIST SP 800-38D).</summary>
    AesGcm,
    /// <summary>ChaCha20 stream cipher with the Poly1305 authenticator (RFC 8439).</summary>
    ChaCha20Poly1305,
}

/// <summary>Which kind of certificate key a TLS 1.2 suite requires the server to sign its key exchange with.</summary>
internal enum ServerAuthentication
{
    /// <summary>TLS 1.3 suites leave authentication to signature_algorithms.</summary>
    Any,
    /// <summary>An ECDSA certificate.</summary>
    Ecdsa,
    /// <summary>An RSA certificate.</summary>
    Rsa,
}

/// <summary>
/// The parameters a cipher suite fixes: protocol version, record AEAD and key sizes, the hash of the key schedule
/// or PRF, and (TLS 1.2 only) the certificate type.
/// </summary>
/// <param name="Suite">The code point.</param>
/// <param name="Version">The one version the suite belongs to.</param>
/// <param name="Aead">Record protection algorithm.</param>
/// <param name="KeyLength">AEAD key length in bytes.</param>
/// <param name="IvLength">
/// Bytes of IV derived per direction: the full 12-byte nonce base in TLS 1.3 (RFC 8446 5.3); the 4-byte implicit
/// "salt" in TLS 1.2 GCM, whose other 8 nonce bytes travel in each record (RFC 5288 3).
/// </param>
/// <param name="Hash">Hash of the TLS 1.3 key schedule and transcript, or of the TLS 1.2 PRF.</param>
/// <param name="Authentication">Certificate key type a TLS 1.2 suite demands.</param>
internal sealed record CipherSuiteInfo(TlsCipherSuite Suite, TlsVersion Version, AeadAlgorithm Aead, int KeyLength,
    int IvLength, HashAlgorithmName Hash, ServerAuthentication Authentication)
{
    /// <summary>Every AEAD used here appends a 16-byte authentication tag.</summary>
    public const int TagLength = 16;
    /// <summary>The per-record AEAD nonce is 96 bits for both GCM and ChaCha20-Poly1305.</summary>
    public const int NonceLength = 12;
    private const int Aes128KeyLength = 16;
    private const int Aes256KeyLength = 32;
    private const int ChaChaKeyLength = 32;
    private const int Tls12GcmSaltLength = 4;

    /// <summary>All supported suites, most preferred first within each version.</summary>
    public static IReadOnlyList<CipherSuiteInfo> All { get; } =
    [
        new(TlsCipherSuite.TlsAes128GcmSha256, TlsVersion.Tls13, AeadAlgorithm.AesGcm, Aes128KeyLength, NonceLength, HashAlgorithmName.SHA256, ServerAuthentication.Any),
        new(TlsCipherSuite.TlsAes256GcmSha384, TlsVersion.Tls13, AeadAlgorithm.AesGcm, Aes256KeyLength, NonceLength, HashAlgorithmName.SHA384, ServerAuthentication.Any),
        new(TlsCipherSuite.TlsChaCha20Poly1305Sha256, TlsVersion.Tls13, AeadAlgorithm.ChaCha20Poly1305, ChaChaKeyLength, NonceLength, HashAlgorithmName.SHA256, ServerAuthentication.Any),
        new(TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256, TlsVersion.Tls12, AeadAlgorithm.AesGcm, Aes128KeyLength, Tls12GcmSaltLength, HashAlgorithmName.SHA256, ServerAuthentication.Ecdsa),
        new(TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384, TlsVersion.Tls12, AeadAlgorithm.AesGcm, Aes256KeyLength, Tls12GcmSaltLength, HashAlgorithmName.SHA384, ServerAuthentication.Ecdsa),
        new(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256, TlsVersion.Tls12, AeadAlgorithm.AesGcm, Aes128KeyLength, Tls12GcmSaltLength, HashAlgorithmName.SHA256, ServerAuthentication.Rsa),
        new(TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384, TlsVersion.Tls12, AeadAlgorithm.AesGcm, Aes256KeyLength, Tls12GcmSaltLength, HashAlgorithmName.SHA384, ServerAuthentication.Rsa),
    ];

    /// <summary>Output length of <see cref="Hash"/>, which is also the length of every TLS 1.3 secret.</summary>
    public int HashLength => HashLengthOf(Hash);

    /// <summary>The suite's parameters, or null for a code point this implementation does not know.</summary>
    public static CipherSuiteInfo? Find(ushort codePoint) => All.FirstOrDefault(info => (ushort)info.Suite == codePoint);

    /// <summary>The suite's parameters.</summary>
    public static CipherSuiteInfo Get(TlsCipherSuite suite) =>
        Find((ushort)suite) ?? throw new ArgumentOutOfRangeException(nameof(suite));

    /// <summary>Output length in bytes of a SHA-2 hash.</summary>
    public static int HashLengthOf(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA256 ? SHA256.HashSizeInBytes :
        hash == HashAlgorithmName.SHA384 ? SHA384.HashSizeInBytes :
        hash == HashAlgorithmName.SHA512 ? SHA512.HashSizeInBytes :
        throw new ArgumentOutOfRangeException(nameof(hash));

    /// <summary>A record cipher keyed with <paramref name="key"/>.</summary>
    public AeadCipher CreateAead(byte[] key) => new(Aead, key);
}
