namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// The cipher suites this implementation speaks, by their IANA code points.
/// </summary>
/// <remarks>
/// <para>
/// A TLS 1.3 suite names only the record protection (an AEAD) and the hash used by the key schedule, e.g.
/// TLS_AES_128_GCM_SHA256. Key exchange and authentication are negotiated separately, by the key_share and
/// signature_algorithms extensions (RFC 8446 B.4).
/// </para>
/// <para>
/// A TLS 1.2 suite bundles everything: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 means ephemeral elliptic-curve
/// Diffie-Hellman key exchange (RFC 8422), a server authenticated by an ECDSA certificate, AES-128 in GCM mode for
/// records (RFC 5288), and SHA-256 for the PRF.
/// </para>
/// </remarks>
public enum TlsCipherSuite : ushort
{
    /// <summary>TLS 1.3: AES-128-GCM records, SHA-256 key schedule. Mandatory to implement (RFC 8446 9.1).</summary>
    TlsAes128GcmSha256 = 0x1301,
    /// <summary>TLS 1.3: AES-256-GCM records, SHA-384 key schedule.</summary>
    TlsAes256GcmSha384 = 0x1302,
    /// <summary>TLS 1.3: ChaCha20-Poly1305 records (RFC 8439), SHA-256 key schedule.</summary>
    TlsChaCha20Poly1305Sha256 = 0x1303,
    /// <summary>TLS 1.2: ECDHE key exchange, ECDSA server certificate, AES-128-GCM, SHA-256 PRF (RFC 5289).</summary>
    TlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B,
    /// <summary>TLS 1.2: ECDHE key exchange, ECDSA server certificate, AES-256-GCM, SHA-384 PRF (RFC 5289).</summary>
    TlsEcdheEcdsaWithAes256GcmSha384 = 0xC02C,
    /// <summary>TLS 1.2: ECDHE key exchange, RSA server certificate, AES-128-GCM, SHA-256 PRF (RFC 5289).</summary>
    TlsEcdheRsaWithAes128GcmSha256 = 0xC02F,
    /// <summary>TLS 1.2: ECDHE key exchange, RSA server certificate, AES-256-GCM, SHA-384 PRF (RFC 5289).</summary>
    TlsEcdheRsaWithAes256GcmSha384 = 0xC030,
}
