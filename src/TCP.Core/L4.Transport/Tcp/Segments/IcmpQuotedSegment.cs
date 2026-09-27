using System.Buffers.Binary;
using System.Net;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>
/// One of our own segments as quoted back inside an ICMP error: its IPv4 header and at least the
/// TCP ports and sequence number (RFC 792 requires the first 8 bytes of the datagram).
/// </summary>
/// <remarks>
/// When a router cannot deliver or forward one of our packets, it returns an ICMP error that quotes the start of
/// that packet. <see cref="TcpHost"/> parses the quote to find which <see cref="TcpConnection"/> sent it. The
/// connection then checks that the quoted sequence number is still in flight, so a forged ICMP message cannot
/// easily tear down or slow a connection (RFC 5927).
/// </remarks>
/// <param name="DestinationAddress">Where our quoted packet was going: the peer's address.</param>
/// <param name="SourcePort">Our port in the quoted segment.</param>
/// <param name="DestinationPort">The peer's port in the quoted segment.</param>
/// <param name="SequenceNumber">Sequence number of the quoted segment.</param>
/// <param name="TotalLength">IPv4 total length of the quoted packet, used to infer an MTU when the router omits one.</param>
internal readonly record struct IcmpQuotedSegment(
    IPAddress DestinationAddress, ushort SourcePort, ushort DestinationPort, uint SequenceNumber, int TotalLength)
{
    private const int MinimumTcpBytes = TcpWireFormat.SequenceNumberOffset + sizeof(uint);
    private const int MinimumQuoteLength = IPv4Packet.MinimumHeaderLength + MinimumTcpBytes;

    /// <summary>The connection that sent the quoted segment.</summary>
    public ConnectionKey Connection => new(SourcePort, DestinationAddress, DestinationPort);

    /// <summary>
    /// Reads the quote at the end of an ICMP error. It must be long enough, name TCP as the protocol, and have a
    /// sane IPv4 header length before any field is trusted.
    /// </summary>
    /// <param name="quote">The ICMP payload: the offending datagram's IPv4 header followed by the start of its TCP header.</param>
    /// <param name="segment">The quoted addressing and sequence number when parsing succeeds.</param>
    /// <returns>False when the quote is not a usable TCP quote and should be ignored.</returns>
    public static bool TryParse(ReadOnlySpan<byte> quote, out IcmpQuotedSegment segment)
    {
        segment = default;
        if (quote.Length < MinimumQuoteLength || quote[IPv4Packet.ProtocolOffset] != (byte)IPv4ProtocolNumber.Tcp) return false;
        var ipHeaderLength =
            (quote[IPv4Packet.VersionAndHeaderLengthOffset] & IPv4Packet.HeaderLengthFieldMask) * IPv4Packet.HeaderLengthUnit;
        if (ipHeaderLength < IPv4Packet.MinimumHeaderLength || quote.Length < ipHeaderLength + MinimumTcpBytes) return false;
        var tcp = quote[ipHeaderLength..];
        segment = new IcmpQuotedSegment(
            DestinationAddress: new IPAddress(quote.Slice(IPv4Packet.DestinationAddressOffset, IPv4Packet.IPv4AddressLength)),
            SourcePort: BinaryPrimitives.ReadUInt16BigEndian(tcp[TcpWireFormat.SourcePortOffset..]),
            DestinationPort: BinaryPrimitives.ReadUInt16BigEndian(tcp[TcpWireFormat.DestinationPortOffset..]),
            SequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(tcp[TcpWireFormat.SequenceNumberOffset..]),
            TotalLength: BinaryPrimitives.ReadUInt16BigEndian(quote[IPv4Packet.TotalLengthOffset..]));
        return true;
    }
}
