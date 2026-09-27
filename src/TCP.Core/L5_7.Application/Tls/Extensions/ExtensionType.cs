namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// Hello extension code points (IANA "TLS ExtensionType Values"). Extensions are how TLS grows: anything not in
/// the fixed hello fields, including the TLS 1.3 version negotiation itself, is an extension.
/// </summary>
/// <remarks>Unknown values are carried through as plain numbers and ignored, as RFC 8446 4.2 requires of a server.</remarks>
internal enum ExtensionType : ushort
{
    /// <summary>Server Name Indication: which host the client wants (RFC 6066 3).</summary>
    ServerName = 0,
    /// <summary>Groups the client can do key exchange in (RFC 8446 4.2.7; "elliptic_curves" in RFC 8422).</summary>
    SupportedGroups = 10,
    /// <summary>TLS 1.2 ECC point encodings (RFC 8422 5.1.2); only "uncompressed" remains.</summary>
    EcPointFormats = 11,
    /// <summary>Signature schemes the sender accepts (RFC 8446 4.2.3).</summary>
    SignatureAlgorithms = 13,
    /// <summary>Application-Layer Protocol Negotiation, e.g. "h2" (RFC 7301).</summary>
    ApplicationLayerProtocolNegotiation = 16,
    /// <summary>Padding to push a ClientHello past sizes that break some middleboxes (RFC 7685).</summary>
    Padding = 21,
    /// <summary>TLS 1.2 extended master secret (RFC 7627).</summary>
    ExtendedMasterSecret = 23,
    /// <summary>Largest record the sender is willing to receive (RFC 8449).</summary>
    RecordSizeLimit = 28,
    /// <summary>TLS 1.2 stateless session tickets (RFC 5077).</summary>
    SessionTicket = 35,
    /// <summary>TLS 1.3 pre-shared key offer; must be last in a ClientHello (RFC 8446 4.2.11).</summary>
    PreSharedKey = 41,
    /// <summary>TLS 1.3 0-RTT data indication (RFC 8446 4.2.10).</summary>
    EarlyData = 42,
    /// <summary>The real version negotiation of TLS 1.3 (RFC 8446 4.2.1).</summary>
    SupportedVersions = 43,
    /// <summary>Opaque state a server may hand back in a HelloRetryRequest (RFC 8446 4.2.2).</summary>
    Cookie = 44,
    /// <summary>Which PSK modes the client supports (RFC 8446 4.2.9).</summary>
    PskKeyExchangeModes = 45,
    /// <summary>The client can authenticate after the handshake (RFC 8446 4.2.6).</summary>
    PostHandshakeAuth = 49,
    /// <summary>Signature schemes accepted inside certificates (RFC 8446 4.2.3).</summary>
    SignatureAlgorithmsCert = 50,
    /// <summary>TLS 1.3 (EC)DHE public keys (RFC 8446 4.2.8).</summary>
    KeyShare = 51,
    /// <summary>TLS 1.2 secure renegotiation indication (RFC 5746).</summary>
    RenegotiationInfo = 0xFF01,
}
