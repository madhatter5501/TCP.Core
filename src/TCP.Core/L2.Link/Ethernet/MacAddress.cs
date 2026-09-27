namespace TCP.L2.Link.Ethernet;

/// <summary>A 48-bit IEEE 802 MAC address: the hardware address that identifies a station on an Ethernet link.</summary>
/// <remarks>
/// Stored in a single <see cref="ulong"/>, so equality, hashing and table lookups are cheap. The low bit of the
/// first octet marks group (multicast or broadcast) addresses, which may appear as a destination but never as a
/// source. <c>default</c> (all zeros) means "unknown" or "none".
/// </remarks>
public readonly record struct MacAddress
{
    private const int AddressLength = EthernetConstants.MacAddressLength;
    private const int BitsPerOctet = 8;
    private const int HexadecimalDigitBits = 4;
    private const int HexadecimalDigitsPerOctet = 2;
    private const int AddressSeparatorCount = AddressLength - 1;
    private const int AddressStringLength = AddressLength * HexadecimalDigitsPerOctet + AddressSeparatorCount;
    private const ulong MulticastAddressBitMask = 0x0100_0000_0000;
    private const ulong AddressMask = 0x0000_FFFF_FFFF_FFFF;
    private const byte HexadecimalNibbleMask = 0x0F;
    private const string HexadecimalDigits = "0123456789ABCDEF";
    private readonly ulong _value;

    /// <summary>Keeps only the low 48 bits.</summary>
    private MacAddress(ulong value) => _value = value & AddressMask;

    /// <summary>FF:FF:FF:FF:FF:FF, which every station on the link receives. ARP requests use it.</summary>
    public static MacAddress Broadcast { get; } = new(AddressMask);

    /// <summary>A group address (multicast, including broadcast): the I/G bit, the low bit of the first octet, is set.</summary>
    public bool IsMulticast => (_value & MulticastAddressBitMask) != 0;

    /// <summary>Reads an address from its 6 wire bytes, most significant first.</summary>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is not exactly 6 bytes.</exception>
    public static MacAddress FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != AddressLength)
        {
            throw new ArgumentException(
                $"A MAC address must contain exactly {AddressLength} bytes.",
                nameof(bytes));
        }

        ulong value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return new MacAddress(value);
    }

    /// <summary>Writes the 6 wire bytes into the start of <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than 6 bytes.</exception>
    public void WriteBytes(Span<byte> destination)
    {
        if (destination.Length < AddressLength)
        {
            throw new ArgumentException(
                $"The destination must contain at least {AddressLength} bytes.",
                nameof(destination));
        }

        for (var index = AddressLength - 1; index >= 0; index--)
        {
            var shift = (AddressLength - 1 - index) * BitsPerOctet;
            destination[index] = (byte)(_value >> shift);
        }
    }

    /// <summary>Colon-separated uppercase hex, such as 02:00:5E:10:00:01.</summary>
    public override string ToString() => string.Create(AddressStringLength, _value, static (text, value) =>
    {
        for (var octetIndex = 0; octetIndex < AddressLength; octetIndex++)
        {
            var shift = (AddressLength - 1 - octetIndex) * BitsPerOctet;
            var octet = (byte)(value >> shift);
            var textIndex = octetIndex * (HexadecimalDigitsPerOctet + 1);
            text[textIndex] = HexadecimalDigits[octet >> HexadecimalDigitBits];
            text[textIndex + 1] = HexadecimalDigits[octet & HexadecimalNibbleMask];
            if (octetIndex < AddressSeparatorCount)
            {
                text[textIndex + HexadecimalDigitsPerOctet] = ':';
            }
        }
    });
}
