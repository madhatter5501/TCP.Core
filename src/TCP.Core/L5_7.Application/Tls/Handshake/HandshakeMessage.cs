using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// One complete handshake message: a type byte, a 3-byte length and the body (RFC 8446 4).
/// </summary>
/// <remarks>
/// <code>
/// struct { HandshakeType msg_type; uint24 length; select (msg_type) { ... } body; } Handshake;
/// </code>
/// <see cref="Raw"/> keeps the header because the transcript hash covers whole messages, header included.
/// </remarks>
internal readonly record struct HandshakeMessage(HandshakeType Type, byte[] Raw)
{
    /// <summary>Type (1) plus length (3).</summary>
    public const int HeaderLength = 4;

    /// <summary>The body without the 4-byte header.</summary>
    public ReadOnlySpan<byte> Body => Raw.AsSpan(HeaderLength);

    /// <summary>Frames <paramref name="body"/> as a message of <paramref name="type"/>.</summary>
    public static byte[] Frame(HandshakeType type, ReadOnlySpan<byte> body)
    {
        var writer = new TlsWriter();
        writer.WriteUInt8((byte)type);
        writer.WriteVector24(body);
        return writer.ToArray();
    }
}
