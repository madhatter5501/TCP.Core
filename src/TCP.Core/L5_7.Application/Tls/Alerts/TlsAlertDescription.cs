namespace TCP.L5_7.Application.Tls.Alerts;

/// <summary>
/// Why an alert was sent (RFC 8446 6, RFC 5246 7.2). Closure alerts end a connection gracefully; error alerts
/// report a failure and are always fatal in TLS 1.3.
/// </summary>
public enum TlsAlertDescription : byte
{
    /// <summary>The sender will send no more data on this connection; the graceful end of a direction (RFC 8446 6.1).</summary>
    CloseNotify = 0,
    /// <summary>A message arrived that is inappropriate at this point of the protocol.</summary>
    UnexpectedMessage = 10,
    /// <summary>A record failed AEAD authentication: tampered with, truncated, or protected with the wrong keys.</summary>
    BadRecordMac = 20,
    /// <summary>A record was longer than the protocol allows.</summary>
    RecordOverflow = 22,
    /// <summary>No acceptable set of security parameters could be agreed.</summary>
    HandshakeFailure = 40,
    /// <summary>A certificate was corrupt or its signatures did not verify.</summary>
    BadCertificate = 42,
    /// <summary>A certificate was of an unsupported type.</summary>
    UnsupportedCertificate = 43,
    /// <summary>A certificate was revoked by its signer.</summary>
    CertificateRevoked = 44,
    /// <summary>A certificate has expired or is not yet valid.</summary>
    CertificateExpired = 45,
    /// <summary>Some other certificate problem made it unacceptable.</summary>
    CertificateUnknown = 46,
    /// <summary>A field was out of range or inconsistent with other fields.</summary>
    IllegalParameter = 47,
    /// <summary>The certificate chain did not lead to a trusted certificate authority.</summary>
    UnknownCa = 48,
    /// <summary>Valid credentials, but access was refused by policy.</summary>
    AccessDenied = 49,
    /// <summary>A message could not be decoded: a length was wrong or a field ran past the end.</summary>
    DecodeError = 50,
    /// <summary>A cryptographic check failed: a signature or a Finished message did not verify.</summary>
    DecryptError = 51,
    /// <summary>The peer's protocol version is recognized but not supported.</summary>
    ProtocolVersion = 70,
    /// <summary>The peer's parameters are weaker than this endpoint requires.</summary>
    InsufficientSecurity = 71,
    /// <summary>A local failure unrelated to the peer or the protocol.</summary>
    InternalError = 80,
    /// <summary>A retried connection used a lower version than the peer supports (RFC 7507).</summary>
    InappropriateFallback = 86,
    /// <summary>The user cancelled the handshake; followed by close_notify.</summary>
    UserCanceled = 90,
    /// <summary>TLS 1.2: a renegotiation request was refused (RFC 5246 7.2.2); sent as a warning.</summary>
    NoRenegotiation = 100,
    /// <summary>A required extension was absent (RFC 8446 9.2).</summary>
    MissingExtension = 109,
    /// <summary>A message carried an extension that is forbidden there or was never offered.</summary>
    UnsupportedExtension = 110,
    /// <summary>The server has no identity for the name in server_name (RFC 6066 3).</summary>
    UnrecognizedName = 112,
    /// <summary>An invalid OCSP response was supplied.</summary>
    BadCertificateStatusResponse = 113,
    /// <summary>No acceptable pre-shared key identity was offered.</summary>
    UnknownPskIdentity = 115,
    /// <summary>The server required a client certificate and none was sent.</summary>
    CertificateRequired = 116,
    /// <summary>The client's ALPN protocols include none the server supports (RFC 7301 3.2).</summary>
    NoApplicationProtocol = 120,
}
