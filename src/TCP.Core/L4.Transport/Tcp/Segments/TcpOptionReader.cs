using static TCP.L4.Transport.Tcp.Segments.TcpWireFormat;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>Walks the options area of a TCP header, skipping padding and rejecting options that overrun it.</summary>
/// <remarks>
/// Options follow the 20-byte fixed header as a type-length-value list, except the single-byte End-of-List
/// and No-Operation kinds. <see cref="TcpOptions"/> decodes every option through this one reader, so the framing
/// rules live in one place. It is a ref struct so it can read a span without copying.
/// </remarks>
internal ref struct TcpOptionReader
{
    private readonly ReadOnlySpan<byte> _options;
    private int _offset;

    /// <summary>Starts reading at the first byte of the options area (header offset 20).</summary>
    public TcpOptionReader(ReadOnlySpan<byte> options) => _options = options;

    /// <summary>Reads the next option, including its kind and length bytes.</summary>
    /// <param name="kind">The option kind.</param>
    /// <param name="option">The whole option, kind and length bytes included.</param>
    /// <param name="offset">Where the option starts within the options area.</param>
    /// <returns>False at the end-of-list option or the end of the options area.</returns>
    public bool TryReadNext(out TcpOptionKind kind, out ReadOnlySpan<byte> option, out int offset)
    {
        while (_offset < _options.Length && _options[_offset] == (byte)TcpOptionKind.NoOperation) _offset++;
        offset = _offset;
        if (_offset >= _options.Length || _options[_offset] == (byte)TcpOptionKind.EndOfList)
        {
            kind = default;
            option = default;
            return false;
        }
        var remaining = _options[_offset..];
        if (remaining.Length <= OptionLengthOffset ||
            remaining[OptionLengthOffset] < OptionHeaderLength ||
            remaining[OptionLengthOffset] > remaining.Length)
            throw new ArgumentException(TcpMessages.InvalidOptionLength);
        kind = (TcpOptionKind)remaining[OptionKindOffset];
        option = remaining[..remaining[OptionLengthOffset]];
        _offset += option.Length;
        return true;
    }
}
