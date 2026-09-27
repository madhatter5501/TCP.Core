using TCP.L5_7.Application.Tls.Alerts;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// Reassembles handshake messages from handshake records. Record and message boundaries are independent: several
/// small messages may share a record, and a large Certificate may span several records (RFC 8446 5.1).
/// </summary>
internal sealed class HandshakeReader
{
    /// <summary>Largest message accepted; generous for certificate chains, small enough to bound memory.</summary>
    public const int MaximumMessageLength = 262_144;

    private readonly List<byte> _buffer = [];

    /// <summary>
    /// Part of a message is buffered. RFC 8446 5.1 forbids a message to span a key change or to be interleaved
    /// with other record types, so callers check this at those points.
    /// </summary>
    public bool HasPartialMessage => _buffer.Count > 0;

    /// <summary>Adds the plaintext of a handshake record.</summary>
    public void Append(ReadOnlySpan<byte> bytes) => _buffer.AddRange(bytes);

    /// <summary>Removes the next complete message, or returns false until it has fully arrived.</summary>
    public bool TryRead(out HandshakeMessage message)
    {
        message = default;
        if (_buffer.Count < HandshakeMessage.HeaderLength) return false;
        var length = _buffer[1] << 16 | _buffer[2] << 8 | _buffer[3];
        if (length > MaximumMessageLength)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.HandshakeMessageTooLong);
        var total = HandshakeMessage.HeaderLength + length;
        if (_buffer.Count < total) return false;
        var raw = _buffer.GetRange(0, total).ToArray();
        _buffer.RemoveRange(0, total);
        message = new HandshakeMessage((HandshakeType)raw[0], raw);
        return true;
    }
}
