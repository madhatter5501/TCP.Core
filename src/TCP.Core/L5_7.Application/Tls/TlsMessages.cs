namespace TCP.L5_7.Application.Tls;

/// <summary>
/// Stable diagnostics for TLS failures. They surface as <see cref="TlsConnection.FailureReason"/> and exception
/// messages, so tests and tools can match them.
/// </summary>
internal static class TlsMessages
{
    // Encoding.
    public const string MessageTruncated = "TLS structure is truncated.";
    public const string TrailingBytes = "TLS structure has trailing bytes.";
    public const string VectorTooLong = "TLS vector exceeds its length prefix.";
    public const string InvalidList = "TLS list is empty or malformed.";

    // Records.
    public const string UnknownContentType = "Record has an unknown content type.";
    public const string NotTls = "Peer is not speaking TLS.";
    public const string RecordTooLong = "Record exceeds the maximum length.";
    public const string PlaintextAfterKeys = "Unprotected record received after keys were established.";
    public const string RecordAuthenticationFailed = "Record failed authentication.";
    public const string AllPadding = "Protected record has no content type.";
    public const string EmptyRecord = "Zero-length handshake record.";
    public const string EarlyApplicationData = "Application data before the handshake completed.";
    public const string InvalidChangeCipherSpec = "Unexpected or malformed ChangeCipherSpec.";
    public const string InvalidAlert = "Malformed alert.";
    public const string MessageSpansBoundary = "Handshake message interrupted by another record type or a key change.";
    public const string HandshakeMessageTooLong = "Handshake message exceeds the size limit.";

    // Alerts and closure.
    public const string PeerAlertFormat = "Peer sent alert {0}.";
    public const string NotWritable = "TLS connection is not open for writing.";
    public const string KeyUpdateUnavailable = "KeyUpdate needs an established TLS 1.3 connection.";
    public const string LocallyAborted = "TLS connection aborted locally.";
    public const string Truncated = "Peer closed the TCP connection without close_notify; data may have been truncated.";
    public const string ClosedDuringHandshake = "Peer closed the TCP connection during the handshake.";
    public const string PeerCanceledHandshake = "Peer sent close_notify before the handshake completed.";

    // Negotiation.
    public const string UnexpectedHandshakeFormat = "Unexpected handshake message {0}.";
    public const string NoCommonVersion = "No TLS version supported by both sides.";
    public const string VersionNotOffered = "Server selected a version the client did not offer.";
    public const string DowngradeDetected = "Server random carries a downgrade marker: TLS 1.3 was removed in transit.";
    public const string InappropriateFallback = "Client fell back to a lower version than both sides support.";
    public const string NoCommonCipherSuite = "No cipher suite supported by both sides.";
    public const string CipherSuiteNotOffered = "Server selected a cipher suite the client did not offer.";
    public const string NoCommonGroup = "No key exchange group supported by both sides.";
    public const string NoCommonSignatureScheme = "No signature scheme supported by both sides.";
    public const string MissingSignatureAlgorithms = "ClientHello lacks signature_algorithms.";
    public const string NoCommonApplicationProtocol = "No ALPN protocol supported by both sides.";
    public const string ProtocolNotOffered = "Server selected an ALPN protocol the client did not offer.";
    public const string CompressionOffered = "Only null compression is allowed.";
    public const string SessionIdTooLong = "legacy_session_id exceeds 32 bytes.";
    public const string SessionIdMismatch = "Server did not echo the client's legacy_session_id.";
    public const string DuplicateExtension = "Extension appears more than once.";
    public const string ExtensionNotOffered = "Server sent an extension the client did not offer.";
    public const string InvalidServerName = "Malformed server_name extension.";
    public const string RecordSizeLimitTooSmall = "record_size_limit is below 64.";
    public const string RenegotiationInfoInvalid = "renegotiation_info must be empty on an initial handshake.";
    public const string NoUncompressedPoints = "Client does not accept uncompressed EC points.";
    public const string UnsupportedCurveType = "ServerKeyExchange must use a named curve.";

    // Key exchange.
    public const string MissingKeyShare = "supported_groups or key_share is missing.";
    public const string DuplicateKeyShare = "key_share lists a group twice.";
    public const string InvalidKeyShare = "Invalid Diffie-Hellman public value.";
    public const string WrongKeyShareGroup = "Key share is for a group that was not requested.";
    public const string RetryChangedHello = "Second ClientHello does not match the first.";
    public const string RetryWrongKeyShare = "Second ClientHello must carry one share for the requested group.";
    public const string SecondHelloRetry = "Server sent a second HelloRetryRequest.";
    public const string KeyScheduleOrder = "Key schedule stage used before it was derived.";
    public const string InvalidKeyUpdate = "KeyUpdate value must be 0 or 1.";

    // Authentication.
    public const string EmptyCertificate = "Server sent no certificate.";
    public const string CertificateUnreadable = "Certificate could not be parsed.";
    public const string CertificateRejected = "Server certificate was rejected.";
    public const string UnexpectedCertificateContext = "Server Certificate has a non-empty request context.";
    public const string SchemeNotOffered = "Signature scheme was not offered or does not fit the cipher suite.";
    public const string SignatureInvalid = "Handshake signature does not verify.";
    public const string FinishedMismatch = "Finished verify_data does not match.";
    public const string UnsupportedKey = "Only ECDSA (P-256, P-384, P-521) and RSA keys are supported.";
    public const string UnsupportedSignatureScheme = "Unsupported signature scheme.";
    public const string CertificateNeedsPrivateKey = "The server certificate must have an ECDSA or RSA private key.";
}
