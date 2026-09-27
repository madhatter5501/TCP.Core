namespace TCP.L2.Link.Ethernet;

/// <summary>Ethernet II, VLAN, and LLC/SNAP wire-format values.</summary>
/// <remarks>
/// Byte offsets and limits shared by <see cref="EthernetFrame"/>, the bridge, and spanning tree. The layout is:
/// <list type="bullet">
/// <item>destination MAC (6 bytes);</item>
/// <item>source MAC (6 bytes);</item>
/// <item>optionally a 4-byte 802.1Q tag (0x8100 plus tag control information);</item>
/// <item>a 2-byte type or length;</item>
/// <item>for 802.3 frames, the 8-byte LLC/SNAP header;</item>
/// <item>the payload.</item>
/// </list>
/// Frames are at least 60 bytes before the 4-byte FCS the hardware appends.
/// </remarks>
public static class EthernetConstants
{
    public const int MacAddressLength = 6;
    public const int DestinationAddressOffset = 0;
    public const int SourceAddressOffset = 6;
    public const int EtherTypeOrLengthOffset = 12;
    public const int HeaderLength = 14;
    public const int VlanControlInformationOffset = 14;
    public const int InnerEtherTypeOffset = 16;
    public const int VlanTagLength = 4;
    public const int LlcSnapProtocolIdentifierLength = 6;
    public const int LlcSnapEtherTypeOffset = 6;
    public const int VlanHeaderLength = 18;
    public const int MinimumFrameLengthWithoutFcs = 60;
    public const int LlcSnapHeaderLength = 8;
    public const int MinimumLlcSnapLength = 8;
    public const ushort Maximum8023Length = 1500;
    public const ushort MinimumEtherTypeValue = 1536;
    public const ushort VlanIdentifierMask = 0x0FFF;
    public const ushort MaximumVlanIdentifier = 4094;
    public const ushort ReservedVlanIdentifier = 4095;
    public const ushort PriorityCodePointMask = 0xE000;
    public const ushort DropEligibleIndicatorMask = 0x1000;

    /// <summary>
    /// LLC header AA-AA-03 (SNAP) plus OUI 00-00-00, which marks the next two bytes as an EtherType: RFC 1042
    /// encapsulation of Ethernet protocols in 802.3 frames.
    /// </summary>
    public static ReadOnlySpan<byte> LlcSnapHeader => [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
}
