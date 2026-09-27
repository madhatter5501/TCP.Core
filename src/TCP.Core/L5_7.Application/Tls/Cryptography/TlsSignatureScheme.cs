namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Signature algorithm plus hash, as offered in signature_algorithms and named in CertificateVerify or a TLS 1.2
/// ServerKeyExchange (RFC 8446 4.2.3).
/// </summary>
/// <remarks>
/// TLS 1.2 wrote these as a (hash, signature) byte pair, e.g. 0x04 = SHA-256 and 0x03 = ECDSA; TLS 1.3 reuses the
/// same values as opaque 16-bit code points and tightens their meaning: an ECDSA scheme also fixes the curve, and
/// PKCS#1 v1.5 RSA signatures are no longer allowed in handshake signatures.
/// </remarks>
public enum TlsSignatureScheme : ushort
{
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256. TLS 1.2 only for handshake signatures.</summary>
    RsaPkcs1Sha256 = 0x0401,
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-384. TLS 1.2 only for handshake signatures.</summary>
    RsaPkcs1Sha384 = 0x0501,
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-512. TLS 1.2 only for handshake signatures.</summary>
    RsaPkcs1Sha512 = 0x0601,
    /// <summary>ECDSA over P-256 with SHA-256.</summary>
    EcdsaSecp256r1Sha256 = 0x0403,
    /// <summary>ECDSA over P-384 with SHA-384.</summary>
    EcdsaSecp384r1Sha384 = 0x0503,
    /// <summary>ECDSA over P-521 with SHA-512.</summary>
    EcdsaSecp521r1Sha512 = 0x0603,
    /// <summary>RSASSA-PSS with SHA-256, for a key in an ordinary rsaEncryption certificate.</summary>
    RsaPssRsaeSha256 = 0x0804,
    /// <summary>RSASSA-PSS with SHA-384, for a key in an ordinary rsaEncryption certificate.</summary>
    RsaPssRsaeSha384 = 0x0805,
    /// <summary>RSASSA-PSS with SHA-512, for a key in an ordinary rsaEncryption certificate.</summary>
    RsaPssRsaeSha512 = 0x0806,
    /// <summary>EdDSA over Ed25519. Recognized, not implemented.</summary>
    Ed25519 = 0x0807,
}
