using System.Buffers.Binary;
using TCP.L5_7.Application.Tls.Alerts;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// Cuts the TCP byte stream into records. TCP delivers bytes, not messages, so one read may hold half a record or
/// several; this buffers until a record's header and its whole fragment have arrived.
/// </summary>
/// <remarks>
/// The header is checked as soon as its 5 bytes arrive, so a peer speaking something else (HTTP, say) is rejected
/// before we wait for a bogus length. Only the version's major byte is checked: RFC 8446 5.1 says the legacy
/// version "MUST be ignored for all purposes", but every TLS record starts with 0x03.
/// </remarks>
internal sealed class RecordReader
{
    private const byte RecordMajorVersion = 0x03;

    private byte[] _buffer = new byte[TlsRecord.HeaderLength];
    private int _start;
    private int _count;

    /// <summary>A record has started arriving but is not complete.</summary>
    public bool HasPartialRecord => _count > 0;

    /// <summary>Appends newly received stream bytes.</summary>
    public void Append(ReadOnlySpan<byte> bytes)
    {
        if (_start + _count + bytes.Length > _buffer.Length)
        {
            var grown = new byte[Math.Max(_buffer.Length * 2, _count + bytes.Length)];
            _buffer.AsSpan(_start, _count).CopyTo(grown);
            _buffer = grown;
            _start = 0;
        }
        bytes.CopyTo(_buffer.AsSpan(_start + _count));
        _count += bytes.Length;
    }

    /// <summary>Removes the next complete record, or returns false until one has fully arrived.</summary>
    /// <exception cref="TlsAlertException">The header names no known content type (unexpected_message), is not TLS,
    /// or announces an oversized fragment (record_overflow).</exception>
    public bool TryRead(out TlsRecord record)
    {
        record = default;
        if (_count < TlsRecord.HeaderLength) return false;
        var header = _buffer.AsSpan(_start, TlsRecord.HeaderLength);
        if (!Enum.IsDefined((ContentType)header[0]) || header[0] == (byte)ContentType.Invalid)
            throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.UnknownContentType);
        if (header[1] != RecordMajorVersion)
            throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.NotTls);
        var length = BinaryPrimitives.ReadUInt16BigEndian(header[3..]);
        if (length > TlsRecord.MaximumTls12CiphertextLength)
            throw new TlsAlertException(TlsAlertDescription.RecordOverflow, TlsMessages.RecordTooLong);
        if (_count < TlsRecord.HeaderLength + length) return false;
        record = new TlsRecord([.. header], [.. _buffer.AsSpan(_start + TlsRecord.HeaderLength, length)]);
        _start += TlsRecord.HeaderLength + length;
        _count -= TlsRecord.HeaderLength + length;
        if (_count == 0) _start = 0;
        return true;
    }
}
