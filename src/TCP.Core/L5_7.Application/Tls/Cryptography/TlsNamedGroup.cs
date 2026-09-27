namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Groups for (EC)DHE key exchange (RFC 8446 4.2.7, RFC 8422 5.1.1). Called "elliptic curves" in TLS 1.2 before
/// finite-field groups were added.
/// </summary>
/// <remarks>
/// .NET provides ECDH over the NIST curves on every platform. X25519 is listed so it can be recognized in a peer's
/// offer, but .NET 10 has no X25519 implementation on macOS, so this stack uses secp256r1 by default. When a
/// client offers only an X25519 key share, the server answers with a HelloRetryRequest asking for secp256r1.
/// </remarks>
public enum TlsNamedGroup : ushort
{
    /// <summary>NIST P-256: 256-bit prime-field Weierstrass curve; the default here.</summary>
    Secp256r1 = 0x0017,
    /// <summary>NIST P-384.</summary>
    Secp384r1 = 0x0018,
    /// <summary>NIST P-521.</summary>
    Secp521r1 = 0x0019,
    /// <summary>Curve25519 in Montgomery form (RFC 7748). Recognized, not implemented.</summary>
    X25519 = 0x001D,
    /// <summary>Curve448 (RFC 7748). Recognized, not implemented.</summary>
    X448 = 0x001E,
    /// <summary>2048-bit finite-field Diffie-Hellman group (RFC 7919). Recognized, not implemented.</summary>
    Ffdhe2048 = 0x0100,
}
