using System.Buffers.Binary;
using TCP.L5_7.Application.Tls.Alerts;

namespace TCP.L5_7.Application.Tls.Wire;

/// <summary>
/// Decodes the TLS presentation language (RFC 8446 3, RFC 5246 4): big-endian integers and variable-length
/// vectors whose length prefix is as wide as their maximum size needs.
/// </summary>
/// <remarks>
/// <para>
/// Every TLS structure is built from a few shapes. <c>uint8</c>, <c>uint16</c> and <c>uint24</c> are unsigned
/// big-endian integers. A vector written <c>opaque data&lt;0..2^16-1&gt;</c> is a 2-byte length followed by that
/// many bytes; <c>&lt;1..2^8-1&gt;</c> gets a 1-byte length and <c>&lt;0..2^24-1&gt;</c> a 3-byte one. Nested
/// structures, such as a list of extensions, are vectors whose contents are read with a fresh reader.
/// </para>
/// <para>
/// Running past the end is a malformed message, which RFC 8446 6.2 answers with a <c>decode_error</c> alert, so
/// every read throws <see cref="TlsAlertException"/> rather than an index exception.
/// </para>
/// </remarks>
internal ref struct TlsReader(ReadOnlySpan<byte> data)
{
    private ReadOnlySpan<byte> _remaining = data;

    /// <summary>Every byte has been consumed.</summary>
    public readonly bool IsEmpty => _remaining.IsEmpty;

    /// <summary>Bytes not yet consumed.</summary>
    public readonly int Remaining => _remaining.Length;

    /// <summary>Reads a <c>uint8</c>.</summary>
    public byte ReadUInt8() => ReadBytes(sizeof(byte))[0];

    /// <summary>Reads a big-endian <c>uint16</c>.</summary>
    public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadBytes(sizeof(ushort)));

    /// <summary>Reads a big-endian <c>uint24</c>, the width TLS uses for handshake and certificate lengths.</summary>
    public int ReadUInt24()
    {
        var bytes = ReadBytes(TlsWriter.UInt24Length);
        return bytes[0] << 16 | bytes[1] << 8 | bytes[2];
    }

    /// <summary>Reads a big-endian <c>uint32</c>.</summary>
    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(sizeof(uint)));

    /// <summary>Consumes exactly <paramref name="count"/> bytes.</summary>
    /// <exception cref="TlsAlertException">Fewer than <paramref name="count"/> bytes remain (decode_error).</exception>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        if (count < 0 || count > _remaining.Length)
            throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.MessageTruncated);
        var bytes = _remaining[..count];
        _remaining = _remaining[count..];
        return bytes;
    }

    /// <summary>Reads a vector with a 1-byte length prefix, <c>&lt;..2^8-1&gt;</c>.</summary>
    public ReadOnlySpan<byte> ReadVector8() => ReadBytes(ReadUInt8());

    /// <summary>Reads a vector with a 2-byte length prefix, <c>&lt;..2^16-1&gt;</c>.</summary>
    public ReadOnlySpan<byte> ReadVector16() => ReadBytes(ReadUInt16());

    /// <summary>Reads a vector with a 3-byte length prefix, <c>&lt;..2^24-1&gt;</c>.</summary>
    public ReadOnlySpan<byte> ReadVector24() => ReadBytes(ReadUInt24());

    /// <summary>
    /// Structures have no trailing padding: bytes left over after the last field mean the lengths disagree with the
    /// contents, which is a <c>decode_error</c>.
    /// </summary>
    public readonly void EnsureEnd()
    {
        if (!_remaining.IsEmpty) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.TrailingBytes);
    }
}
