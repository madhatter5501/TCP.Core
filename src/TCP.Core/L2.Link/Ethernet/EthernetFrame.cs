using System.Buffers.Binary;

namespace TCP.L2.Link.Ethernet;

/// <summary>Ethernet II or IEEE 802.3 LLC/SNAP, optionally single-tagged. Excludes preamble and FCS.</summary>
/// <remarks>
/// <para>
/// The frame is the link layer's unit of delivery. Destination and source MAC addresses are followed by a 16-bit
/// field. At 1536 or above it is an EtherType naming the payload's protocol (Ethernet II). At 1500 or below it is
/// the payload length, and an 802.2 LLC/SNAP header then carries the EtherType. An optional 802.1Q tag in
/// between assigns the frame to a VLAN.
/// </para>
/// <para>
/// This immutable value decodes both encapsulations into one shape, so <see cref="EtherType"/> always names the
/// payload protocol. The network card handles the preamble and the frame check sequence, so neither appears here.
/// </para>
/// </remarks>
/// <param name="Destination">Receiving station, or a broadcast or multicast group.</param>
/// <param name="Source">Sending station; always unicast.</param>
/// <param name="EtherType">Protocol of <paramref name="Payload"/>; see <see cref="Ethernet.EtherType"/>.</param>
/// <param name="Payload">The carried packet. After <see cref="Parse"/> it may include padding the sender added to reach 60 bytes.</param>
/// <param name="VlanTag">The 802.1Q tag control information (priority, drop eligibility and VLAN ID), or null when untagged.</param>
/// <param name="UsesLlcSnap">Whether the frame uses 802.3 length plus LLC/SNAP instead of an Ethernet II type field.</param>
public readonly record struct EthernetFrame(MacAddress Destination, MacAddress Source, ushort EtherType,
    ReadOnlyMemory<byte> Payload, ushort? VlanTag = null, bool UsesLlcSnap = false)
{
    /// <summary>Decodes a frame as captured from the wire, without preamble or FCS.</summary>
    /// <exception cref="ArgumentException">
    /// The frame is truncated, uses the reserved VLAN ID, has an invalid 802.3 length, has an unsupported LLC
    /// header, or has a reserved type/length value.
    /// </exception>
    public static EthernetFrame Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < EthernetConstants.HeaderLength) throw new ArgumentException("Truncated Ethernet header.", nameof(bytes));

        var typeOrLength = ReadUInt16(bytes, EthernetConstants.EtherTypeOrLengthOffset);
        var headerLength = EthernetConstants.HeaderLength;
        ushort? vlanTag = null;
        if (typeOrLength == (ushort)Ethernet.EtherType.VlanTag)
        {
            vlanTag = ReadVlanTag(bytes);
            typeOrLength = ReadUInt16(bytes, EthernetConstants.InnerEtherTypeOffset);
            headerLength = EthernetConstants.VlanHeaderLength;
        }

        var usesLlcSnap = typeOrLength <= EthernetConstants.Maximum8023Length;
        ReadOnlySpan<byte> payload;
        var etherType = usesLlcSnap
            ? ReadLlcSnapPayload(bytes, headerLength, typeOrLength, out payload)
            : ReadEthernetIIPayload(bytes, headerLength, typeOrLength, out payload);

        var destination = MacAddress.FromBytes(bytes.Slice(EthernetConstants.DestinationAddressOffset, EthernetConstants.MacAddressLength));
        var source = MacAddress.FromBytes(bytes.Slice(EthernetConstants.SourceAddressOffset, EthernetConstants.MacAddressLength));
        return new EthernetFrame(destination, source, etherType, payload.ToArray(), vlanTag, usesLlcSnap);
    }

    /// <summary>Encodes the frame, padding it to the 60-byte Ethernet minimum.</summary>
    /// <exception cref="ArgumentException">The EtherType is missing, the VLAN ID is reserved, or an LLC/SNAP payload exceeds 1500 bytes.</exception>
    public byte[] Serialize()
    {
        if (EtherType < EthernetConstants.MinimumEtherTypeValue) throw new ArgumentException("An EtherType is required.");
        if (VlanTag is { } tag && IsReservedVlan(tag)) throw new ArgumentException("Reserved VLAN identifier.");

        var headerLength = VlanTag.HasValue ? EthernetConstants.VlanHeaderLength : EthernetConstants.HeaderLength;
        var snapLength = UsesLlcSnap ? EthernetConstants.LlcSnapHeaderLength : 0;
        var dataLength = Payload.Length + snapLength;
        if (UsesLlcSnap && dataLength > EthernetConstants.Maximum8023Length)
            throw new ArgumentException("LLC/SNAP exceeds the Ethernet length limit.");

        var bytes = new byte[Math.Max(EthernetConstants.MinimumFrameLengthWithoutFcs, headerLength + dataLength)];
        WriteAddressesAndTag(bytes);
        WriteUInt16(bytes, headerLength - sizeof(ushort), UsesLlcSnap ? (ushort)dataLength : EtherType);
        if (UsesLlcSnap)
        {
            EthernetConstants.LlcSnapHeader.CopyTo(bytes.AsSpan(headerLength));
            WriteUInt16(bytes, headerLength + EthernetConstants.LlcSnapEtherTypeOffset, EtherType);
        }
        Payload.Span.CopyTo(bytes.AsSpan(headerLength + snapLength));
        return bytes;
    }

    /// <summary>Reads the 802.1Q tag control information that follows the 0x8100 tag type.</summary>
    private static ushort ReadVlanTag(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < EthernetConstants.VlanHeaderLength) throw new ArgumentException("Truncated VLAN header.", nameof(bytes));
        var tag = ReadUInt16(bytes, EthernetConstants.VlanControlInformationOffset);
        if (IsReservedVlan(tag)) throw new ArgumentException("Reserved VLAN identifier.", nameof(bytes));
        return tag;
    }

    /// <summary>
    /// IEEE 802.3: the type field is a length, and the data starts with an LLC/SNAP header whose last two bytes are
    /// the real EtherType. Only the SNAP header for EtherType encapsulation (RFC 1042) is supported.
    /// </summary>
    /// <returns>The EtherType from the SNAP header.</returns>
    private static ushort ReadLlcSnapPayload(ReadOnlySpan<byte> bytes, int headerLength, ushort length, out ReadOnlySpan<byte> payload)
    {
        if (length < EthernetConstants.MinimumLlcSnapLength || bytes.Length - headerLength < length)
            throw new ArgumentException("Invalid IEEE 802.3 length.", nameof(bytes));
        var llcSnapData = bytes.Slice(headerLength, length);
        if (!llcSnapData[..EthernetConstants.LlcSnapProtocolIdentifierLength].SequenceEqual(EthernetConstants.LlcSnapHeader))
            throw new ArgumentException("Unsupported LLC/SNAP encapsulation.", nameof(bytes));
        payload = llcSnapData[EthernetConstants.LlcSnapHeaderLength..];
        return ReadUInt16(llcSnapData, EthernetConstants.LlcSnapEtherTypeOffset);
    }

    /// <summary>Ethernet II: the type field is the EtherType, and the payload runs to the end of the frame.</summary>
    /// <returns><paramref name="etherType"/>, once checked not to be a reserved value.</returns>
    private static ushort ReadEthernetIIPayload(
        ReadOnlySpan<byte> bytes, int headerLength, ushort etherType, out ReadOnlySpan<byte> payload)
    {
        if (etherType < EthernetConstants.MinimumEtherTypeValue)
            throw new ArgumentException("Reserved Ethernet type/length field.", nameof(bytes));
        payload = bytes[headerLength..];
        return etherType;
    }

    /// <summary>Writes both MAC addresses and, for a tagged frame, the 802.1Q tag.</summary>
    private void WriteAddressesAndTag(byte[] bytes)
    {
        Destination.WriteBytes(bytes.AsSpan(EthernetConstants.DestinationAddressOffset, EthernetConstants.MacAddressLength));
        Source.WriteBytes(bytes.AsSpan(EthernetConstants.SourceAddressOffset, EthernetConstants.MacAddressLength));
        if (VlanTag is not { } vlanTag) return;
        WriteUInt16(bytes, EthernetConstants.EtherTypeOrLengthOffset, (ushort)Ethernet.EtherType.VlanTag);
        WriteUInt16(bytes, EthernetConstants.VlanControlInformationOffset, vlanTag);
    }

    /// <summary>VLAN ID 4095 is reserved by 802.1Q and must never appear on the wire.</summary>
    private static bool IsReservedVlan(ushort tag) =>
        (tag & EthernetConstants.VlanIdentifierMask) == EthernetConstants.ReservedVlanIdentifier;

    /// <summary>Reads a big-endian (network order) 16-bit field.</summary>
    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, sizeof(ushort)));

    /// <summary>Writes a big-endian (network order) 16-bit field.</summary>
    private static void WriteUInt16(byte[] bytes, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), value);
}
