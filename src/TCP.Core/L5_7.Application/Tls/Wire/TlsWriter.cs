using System.Buffers.Binary;

namespace TCP.L5_7.Application.Tls.Wire;

/// <summary>
/// Encodes the TLS presentation language (RFC 8446 3): big-endian integers and length-prefixed vectors. The
/// counterpart of <see cref="TlsReader"/>.
/// </summary>
/// <remarks>
/// A vector's length is only known once its contents are written, so <see cref="OpenVector"/> reserves the
/// prefix and the returned scope fills it in when disposed:
/// <code>
/// using (writer.OpenVector(2)) { writer.WriteUInt16(0x0304); }  // 00 02 03 04
/// </code>
/// </remarks>
internal sealed class TlsWriter
{
    /// <summary>Width of a <c>uint24</c>.</summary>
    public const int UInt24Length = 3;
    private const int InitialCapacity = 256;

    private byte[] _buffer = new byte[InitialCapacity];

    /// <summary>Bytes written so far.</summary>
    public int Length { get; private set; }

    /// <summary>The bytes written so far.</summary>
    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, Length);

    /// <summary>Writes a <c>uint8</c>.</summary>
    public void WriteUInt8(int value) => Reserve(sizeof(byte))[0] = checked((byte)value);

    /// <summary>Writes a big-endian <c>uint16</c>.</summary>
    public void WriteUInt16(int value) => BinaryPrimitives.WriteUInt16BigEndian(Reserve(sizeof(ushort)), checked((ushort)value));

    /// <summary>Writes a big-endian <c>uint24</c>.</summary>
    public void WriteUInt24(int value)
    {
        if (value is < 0 or > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(value));
        var span = Reserve(UInt24Length);
        span[0] = (byte)(value >> 16);
        span[1] = (byte)(value >> 8);
        span[2] = (byte)value;
    }

    /// <summary>Writes a big-endian <c>uint32</c>.</summary>
    public void WriteUInt32(uint value) => BinaryPrimitives.WriteUInt32BigEndian(Reserve(sizeof(uint)), value);

    /// <summary>Writes raw bytes with no length prefix.</summary>
    public void WriteBytes(ReadOnlySpan<byte> bytes) => bytes.CopyTo(Reserve(bytes.Length));

    /// <summary>Writes <paramref name="bytes"/> as a vector with a 1-byte length prefix.</summary>
    public void WriteVector8(ReadOnlySpan<byte> bytes) { WriteUInt8(bytes.Length); WriteBytes(bytes); }

    /// <summary>Writes <paramref name="bytes"/> as a vector with a 2-byte length prefix.</summary>
    public void WriteVector16(ReadOnlySpan<byte> bytes) { WriteUInt16(bytes.Length); WriteBytes(bytes); }

    /// <summary>Writes <paramref name="bytes"/> as a vector with a 3-byte length prefix.</summary>
    public void WriteVector24(ReadOnlySpan<byte> bytes) { WriteUInt24(bytes.Length); WriteBytes(bytes); }

    /// <summary>
    /// Starts a vector whose length prefix is <paramref name="prefixLength"/> bytes (1, 2 or 3). Everything written
    /// until the returned scope is disposed becomes its contents.
    /// </summary>
    public VectorScope OpenVector(int prefixLength)
    {
        if (prefixLength is < 1 or > UInt24Length) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        var start = Length;
        Reserve(prefixLength);
        return new VectorScope(this, start, prefixLength);
    }

    /// <summary>A copy of everything written.</summary>
    public byte[] ToArray() => [.. WrittenSpan];

    /// <summary>Extends the written region by <paramref name="count"/> bytes, growing storage by doubling.</summary>
    private Span<byte> Reserve(int count)
    {
        if (Length + count > _buffer.Length)
            Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, Length + count));
        var span = _buffer.AsSpan(Length, count);
        Length += count;
        return span;
    }

    /// <summary>Fills in a reserved length prefix once the vector's contents are written.</summary>
    public readonly struct VectorScope : IDisposable
    {
        private readonly TlsWriter _writer;
        private readonly int _start;
        private readonly int _prefixLength;

        internal VectorScope(TlsWriter writer, int start, int prefixLength)
        {
            _writer = writer;
            _start = start;
            _prefixLength = prefixLength;
        }

        /// <summary>Writes the contents' length into the prefix; throws if it exceeds what the prefix can express.</summary>
        public void Dispose()
        {
            var length = _writer.Length - _start - _prefixLength;
            if (length >= 1 << (8 * _prefixLength)) throw new InvalidOperationException(TlsMessages.VectorTooLong);
            var prefix = _writer._buffer.AsSpan(_start, _prefixLength);
            for (var i = _prefixLength - 1; i >= 0; i--, length >>= 8) prefix[i] = (byte)length;
        }
    }
}
