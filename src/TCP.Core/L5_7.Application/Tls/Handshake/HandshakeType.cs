namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>The first byte of every handshake message (RFC 8446 4, RFC 5246 7.4).</summary>
internal enum HandshakeType : byte
{
    /// <summary>TLS 1.2: a server's request to renegotiate. Refused here.</summary>
    HelloRequest = 0,
    /// <summary>Opens the handshake: versions, suites, randomness and extensions the client offers.</summary>
    ClientHello = 1,
    /// <summary>The server's choices; in TLS 1.3 a special random marks a HelloRetryRequest.</summary>
    ServerHello = 2,
    /// <summary>A resumption ticket, sent after the handshake. Ignored here.</summary>
    NewSessionTicket = 4,
    /// <summary>TLS 1.3 end of 0-RTT data. Not used here.</summary>
    EndOfEarlyData = 5,
    /// <summary>TLS 1.3: server extensions that need not be visible, encrypted under the handshake keys.</summary>
    EncryptedExtensions = 8,
    /// <summary>A certificate chain, leaf first.</summary>
    Certificate = 11,
    /// <summary>TLS 1.2: the server's signed ephemeral key exchange parameters.</summary>
    ServerKeyExchange = 12,
    /// <summary>The server asks for a client certificate.</summary>
    CertificateRequest = 13,
    /// <summary>TLS 1.2: the end of the server's first flight.</summary>
    ServerHelloDone = 14,
    /// <summary>TLS 1.3: a signature over the transcript by the certificate's key.</summary>
    CertificateVerify = 15,
    /// <summary>TLS 1.2: the client's ephemeral public key.</summary>
    ClientKeyExchange = 16,
    /// <summary>A MAC over the whole handshake; the first message protected by the new keys.</summary>
    Finished = 20,
    /// <summary>TLS 1.3: switch to the next generation of traffic keys.</summary>
    KeyUpdate = 24,
    /// <summary>TLS 1.3: stands in for ClientHello1 in the transcript after a HelloRetryRequest.</summary>
    MessageHash = 254,
}
