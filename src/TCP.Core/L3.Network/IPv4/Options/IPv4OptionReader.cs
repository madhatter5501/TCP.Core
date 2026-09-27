namespace TCP.L3.Network.IPv4.Options;

/// <summary>One option inside an IPv4 header's options area.</summary>
/// <param name="type">The option type octet.</param>
/// <param name="offset">Index of the type octet within the options area.</param>
/// <param name="bytes">The whole option: type, length and data. One byte for No-Operation.</param>
internal readonly ref struct IPv4Option(IPv4OptionType type, int offset, ReadOnlySpan<byte> bytes)
{
    /// <summary>Index of the length octet relative to the option's start.</summary>
    public const int LengthFieldOffset = 1;

    /// <summary>Index of the pointer octet relative to the option's start, for options that carry one.</summary>
    public const int PointerFieldOffset = 2;

    /// <summary>The option's type octet.</summary>
    public IPv4OptionType Type { get; } = type;

    /// <summary>Index of the option's type octet within the options area.</summary>
    public int Offset { get; } = offset;

    /// <summary>The option's bytes, including its type and length octets.</summary>
    public ReadOnlySpan<byte> Bytes { get; } = bytes;

    /// <summary>Total option length in octets, as its length field states (1 for No-Operation).</summary>
    public int Length => Bytes.Length;

    /// <summary>Index within the options area of the octet at <paramref name="relativeOffset"/> inside this option.</summary>
    public int FieldIndex(int relativeOffset) => Offset + relativeOffset;
}

/// <summary>
/// Walks the options area of an IPv4 header (RFC 791 3.1). Single-octet End-of-List stops the walk and
/// No-Operation is returned as a one-byte option, so callers can reproduce padding. Every other option is a
/// type-length-value, and one whose length overruns the area ends the walk with <see cref="IsMalformed"/> set.
/// </summary>
/// <remarks>
/// The header processing in <see cref="IPv4Options"/> previously repeated this loop in five places; they now
/// share this reader, so there is one definition of IPv4 option framing.
/// </remarks>
internal ref struct IPv4OptionReader
{
    private const int MinimumOptionLength = 2;

    private readonly ReadOnlySpan<byte> _options;
    private int _offset;

    /// <summary>Starts at the first octet of the options area, which follows the 20-byte fixed header.</summary>
    public IPv4OptionReader(ReadOnlySpan<byte> options) => _options = options;

    /// <summary>The walk stopped at an option whose length field is missing, too small, or overruns the area.</summary>
    public bool IsMalformed { get; private set; }

    /// <summary>When <see cref="IsMalformed"/>, the index of the offending length octet within the options area.</summary>
    public int MalformedFieldIndex => _offset + IPv4Option.LengthFieldOffset;

    /// <summary>Reads the next option.</summary>
    /// <returns>False at End-of-List, at the end of the area, or on malformed framing.</returns>
    public bool TryReadNext(out IPv4Option option)
    {
        option = default;
        if (_offset >= _options.Length) return false;
        var type = (IPv4OptionType)_options[_offset];
        if (type == IPv4OptionType.EndOfList) return false;
        var length = type == IPv4OptionType.NoOperation ? 1 : ReadLength();
        if (length == 0)
        {
            IsMalformed = true;
            return false;
        }
        option = new IPv4Option(type, _offset, _options.Slice(_offset, length));
        _offset += length;
        return true;
    }

    /// <returns>The option's length, or 0 when its framing is invalid.</returns>
    private readonly int ReadLength()
    {
        var lengthIndex = _offset + IPv4Option.LengthFieldOffset;
        if (lengthIndex >= _options.Length) return 0;
        var length = _options[lengthIndex];
        return length < MinimumOptionLength || _offset + length > _options.Length ? 0 : length;
    }
}
