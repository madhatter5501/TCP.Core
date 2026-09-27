namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// The first byte of every record: which higher-level protocol its payload belongs to (RFC 8446 5.1).
/// </summary>
/// <remarks>
/// TLS multiplexes four sub-protocols over one byte stream. In TLS 1.3 an encrypted record always shows
/// <see cref="ApplicationData"/> on the outside; the real type travels inside the encryption, so an observer cannot
/// tell handshake messages from alerts or data.
/// </remarks>
internal enum ContentType : byte
{
    /// <summary>Never valid on the wire; marks padding in a TLS 1.3 inner plaintext.</summary>
    Invalid = 0,
    /// <summary>TLS 1.2: "switch to the negotiated keys now". TLS 1.3 keeps a dummy one for middlebox compatibility.</summary>
    ChangeCipherSpec = 20,
    /// <summary>A two-byte alert: level and description.</summary>
    Alert = 21,
    /// <summary>Handshake messages, which may be coalesced into, or fragmented across, records.</summary>
    Handshake = 22,
    /// <summary>The application's bytes, and in TLS 1.3 the outer type of every encrypted record.</summary>
    ApplicationData = 23,
}
