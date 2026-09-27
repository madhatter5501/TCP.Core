using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TCP.Checksums;

namespace TCP.L3.Network.IPv4;

/// <summary>An IPv4 datagram (RFC 791): header fields, options and payload. The wire codec for the network layer.</summary>
/// <remarks>
/// <para>
/// The datagram is IP's unit of delivery. The header says where it comes from and goes to, how long it may live
/// (TTL), which protocol it carries, and how it was fragmented.
/// </para>
/// <para>
/// This immutable value is the boundary between bytes and meaning. The link hands raw bytes to
/// <see cref="Parse"/>, and <see cref="Serialize"/> produces bytes for the link. Version, header length and total
/// length are derived, and the header checksum is computed on output and verified on input.
/// </para>
/// </remarks>
/// <param name="TypeOfService">DSCP (upper 6 bits) and ECN (lower 2 bits).</param>
/// <param name="Identification">Groups the fragments of one datagram; see <see cref="Fragmentation.IPv4FragmentField"/>.</param>
/// <param name="FlagsAndFragmentOffset">The DF and MF flags and the fragment offset, packed as on the wire.</param>
/// <param name="TimeToLive">Hop limit; routers decrement it and discard at zero.</param>
/// <param name="Protocol">The payload's protocol; see <see cref="IPv4ProtocolNumber"/>.</param>
/// <param name="SourceAddress">Sender's IPv4 address.</param>
/// <param name="DestinationAddress">Final recipient's IPv4 address.</param>
/// <param name="Options">Raw option bytes, a multiple of 4 and at most 40; see <see cref="Options.IPv4Options"/>.</param>
/// <param name="Payload">The carried upper-layer message, or one fragment of it.</param>
public readonly record struct IPv4Packet(
    byte TypeOfService,
    ushort Identification,
    ushort FlagsAndFragmentOffset,
    byte TimeToLive,
    byte Protocol,
    IPAddress SourceAddress,
    IPAddress DestinationAddress,
    ReadOnlyMemory<byte> Options,
    ReadOnlyMemory<byte> Payload)
{
    /// <summary>Length of a header without options.</summary>
    public const int MinimumHeaderLength = 20;
    /// <summary>Largest datagram the 16-bit Total Length field can describe.</summary>
    public const int MaximumTotalLength = ushort.MaxValue;
    /// <summary>Largest payload, reached when the header carries no options.</summary>
    public const int MaximumPayloadLength = MaximumTotalLength - MinimumHeaderLength;
    private const int MaximumHeaderLength = 60;
    internal const int HeaderLengthUnit = 4;
    internal const int VersionAndHeaderLengthOffset = 0;
    private const int TypeOfServiceOffset = 1;
    internal const int TotalLengthOffset = 2;
    internal const int IdentificationOffset = 4;
    private const int FlagsAndFragmentOffsetOffset = 6;
    private const int TimeToLiveOffset = 8;
    internal const int ProtocolOffset = 9;
    private const int HeaderChecksumOffset = 10;
    internal const int SourceAddressOffset = 12;
    internal const int DestinationAddressOffset = 16;
    internal const int IPv4AddressLength = 4;
    internal const int VersionFieldShift = 4;
    internal const byte IPv4Version = 4;
    internal const byte HeaderLengthFieldMask = 0x0F;

    /// <summary>Header size in bytes: 20 plus options.</summary>
    public int HeaderLength => MinimumHeaderLength + Options.Length;

    /// <summary>Whole datagram size in bytes, as written into the Total Length field and compared against MTUs.</summary>
    public int TotalLength => HeaderLength + Payload.Length;

    /// <summary>
    /// Decodes and validates a datagram: version 4, a sane header length, a total length that fits the buffer, and
    /// a correct header checksum. Bytes past Total Length, such as Ethernet padding, are ignored. Options and
    /// payload are copied, so the result outlives the buffer.
    /// </summary>
    /// <exception cref="ArgumentException">The bytes are not a valid IPv4 datagram.</exception>
    public static IPv4Packet Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < MinimumHeaderLength)
        {
            throw new ArgumentException(
                $"An IPv4 packet must contain at least a {MinimumHeaderLength}-byte header.",
                nameof(bytes));
        }

        var versionAndHeaderLength = bytes[VersionAndHeaderLengthOffset];
        if ((versionAndHeaderLength >> VersionFieldShift) != IPv4Version)
        {
            throw new ArgumentException("The packet is not IPv4.", nameof(bytes));
        }

        var headerLength =
            (versionAndHeaderLength & HeaderLengthFieldMask) * HeaderLengthUnit;
        if (headerLength < MinimumHeaderLength ||
            headerLength > MaximumHeaderLength ||
            bytes.Length < headerLength)
        {
            throw new ArgumentException("The IPv4 header length is invalid or truncated.", nameof(bytes));
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(
            bytes.Slice(TotalLengthOffset, sizeof(ushort)));
        if (totalLength < headerLength || totalLength > bytes.Length)
        {
            throw new ArgumentException("The IPv4 total length is inconsistent with the header or available data.", nameof(bytes));
        }

        if (!InternetChecksum.IsValid(bytes[..headerLength]))
        {
            throw new ArgumentException("The IPv4 header checksum is invalid.", nameof(bytes));
        }

        return new IPv4Packet(
            bytes[TypeOfServiceOffset],
            BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(IdentificationOffset, sizeof(ushort))),
            BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(FlagsAndFragmentOffsetOffset, sizeof(ushort))),
            bytes[TimeToLiveOffset],
            bytes[ProtocolOffset],
            new IPAddress(bytes.Slice(SourceAddressOffset, IPv4AddressLength)),
            new IPAddress(bytes.Slice(DestinationAddressOffset, IPv4AddressLength)),
            bytes.Slice(MinimumHeaderLength, headerLength - MinimumHeaderLength).ToArray(),
            bytes.Slice(headerLength, totalLength - headerLength).ToArray());
    }

    /// <summary>Encodes the datagram, filling in version, header length, total length and header checksum.</summary>
    /// <exception cref="ArgumentException">Options are misaligned or too long, the datagram is too large, or an address is not IPv4.</exception>
    public byte[] Serialize()
    {
        if (Options.Length > MaximumHeaderLength - MinimumHeaderLength ||
            Options.Length % HeaderLengthUnit != 0)
        {
            throw new ArgumentException(
                $"IPv4 options must be word-aligned and fit within the {MaximumHeaderLength}-byte header limit.",
                nameof(Options));
        }

        var headerLength = MinimumHeaderLength + Options.Length;
        var totalLength = headerLength + Payload.Length;
        if (totalLength > MaximumTotalLength)
        {
            throw new ArgumentException("An IPv4 packet cannot exceed 65,535 bytes.", nameof(Payload));
        }

        var bytes = new byte[totalLength];
        bytes[VersionAndHeaderLengthOffset] =
            (byte)((IPv4Version << VersionFieldShift) | (headerLength / HeaderLengthUnit));
        bytes[TypeOfServiceOffset] = TypeOfService;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(TotalLengthOffset), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(IdentificationOffset), Identification);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(FlagsAndFragmentOffsetOffset), FlagsAndFragmentOffset);
        bytes[TimeToLiveOffset] = TimeToLive;
        bytes[ProtocolOffset] = Protocol;
        WriteIPv4Address(
            SourceAddress,
            bytes.AsSpan(SourceAddressOffset, IPv4AddressLength),
            nameof(SourceAddress));
        WriteIPv4Address(
            DestinationAddress,
            bytes.AsSpan(DestinationAddressOffset, IPv4AddressLength),
            nameof(DestinationAddress));
        Options.Span.CopyTo(bytes.AsSpan(MinimumHeaderLength, Options.Length));
        Payload.Span.CopyTo(bytes.AsSpan(headerLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            bytes.AsSpan(HeaderChecksumOffset),
            InternetChecksum.Compute(bytes.AsSpan(0, headerLength)));
        return bytes;
    }

    /// <summary>Writes a 4-byte address, rejecting null or IPv6 addresses with an error naming the offending field.</summary>
    private static void WriteIPv4Address(IPAddress address, Span<byte> destination, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(address, parameterName);
        if (address.AddressFamily != AddressFamily.InterNetwork ||
            !address.TryWriteBytes(destination, out var written) || written != IPv4AddressLength)
        {
            throw new ArgumentException("IPv4 packet addresses must be IPv4 addresses.", parameterName);
        }
    }
}
