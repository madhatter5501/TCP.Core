using TCP.L3.Network.IPv4;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>
/// TCP wire layout in bytes (RFC 9293 3.1) and the fixed values the stack writes. <see cref="TcpSegment"/> reads
/// and writes headers through these offsets so no magic numbers appear in the codec. The checksum pseudo-header is
/// shared with UDP in <see cref="Checksums.PseudoHeader"/>.
/// </summary>
internal static class TcpWireFormat
{
    public const int MinimumHeaderLength = 20;
    public const int MaximumHeaderLength = 60;
    public const int MaximumOptionsLength = MaximumHeaderLength - MinimumHeaderLength;
    public const int HeaderWordLength = 4;
    public const int DataOffsetShift = 4;
    public const int SourcePortOffset = 0;
    public const int DestinationPortOffset = SourcePortOffset + sizeof(ushort);
    public const int SequenceNumberOffset = DestinationPortOffset + sizeof(ushort);
    public const int AcknowledgmentNumberOffset = SequenceNumberOffset + sizeof(uint);
    public const int DataOffsetOffset = AcknowledgmentNumberOffset + sizeof(uint);
    public const int FlagsOffset = DataOffsetOffset + sizeof(byte);
    public const int WindowOffset = FlagsOffset + sizeof(byte);
    public const int ChecksumOffset = WindowOffset + sizeof(ushort);
    public const int UrgentPointerOffset = ChecksumOffset + sizeof(ushort);
    public const int MaximumSegmentLength = IPv4Packet.MaximumPayloadLength;
    public const int IPv4AndTcpHeaderLength = IPv4Packet.MinimumHeaderLength + MinimumHeaderLength;
    public const uint ControlSequenceLength = 1;
    public const uint UnusedAcknowledgmentNumber = 0;
    public const uint ResetSequenceNumber = 0;
    public const ushort ResetWindow = 0;
    public const ushort NoUrgentPointer = 0;
    /// <summary>Assumed peer MSS when a SYN carries no MSS option (RFC 9293): 576 - 20 - 20 = 536.</summary>
    public const ushort DefaultIPv4Mss = IPv4Constants.MinimumReassemblyLength - IPv4AndTcpHeaderLength;
    public const int MaximumUnscaledWindow = ushort.MaxValue;
    /// <summary>IPv6 payload limit without jumbograms: the 16-bit Payload Length field.</summary>
    public const int MaximumIPv6SegmentLength = ushort.MaxValue;
    public const int OptionKindOffset = 0;
    public const int OptionLengthOffset = 1;
    public const int OptionHeaderLength = 2;
    public const int MssOptionLength = OptionHeaderLength + sizeof(ushort);
}
