using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TCP.Checksums;
using TCP.L3.Network.IPv4;

namespace TCP.L4.Transport.Udp;

/// <summary>UDP wire codec (RFC 768). Checksum includes the IPv4 or IPv6 pseudo-header. All multibyte values use network order.</summary>
/// <remarks>
/// <para>
/// UDP adds almost nothing to IP: two ports to pick the application, a length, and a checksum. There is no
/// connection, ordering, retransmission or flow control; each datagram stands alone and may be lost, duplicated
/// or reordered. That thinness is the point: DNS, DHCP, streaming media and QUIC build exactly the reliability
/// they need on top.
/// </para>
/// <para>
/// This immutable value is the boundary between bytes and meaning: <see cref="UdpHost"/> calls <see cref="Parse"/>
/// on every arriving datagram and <see cref="Serialize"/> on everything it sends. Invalid input throws
/// <see cref="ArgumentException"/>, which the host treats as "drop silently".
/// </para>
/// </remarks>
/// <param name="SourcePort">Sender's port; zero when the sender expects no reply.</param>
/// <param name="DestinationPort">Receiver's port.</param>
/// <param name="Payload">The application message.</param>
public readonly record struct UdpDatagram(ushort SourcePort, ushort DestinationPort, ReadOnlyMemory<byte> Payload)
{
    /// <summary>The fixed 8-byte header: source port, destination port, length and checksum.</summary>
    public const int HeaderLength = 8;
    /// <summary>Largest payload one IPv4 datagram can carry: 65,535 - 20 (IPv4 header) - 8 (UDP header) = 65,507.</summary>
    public const int MaximumIPv4PayloadLength = IPv4Packet.MaximumPayloadLength - HeaderLength;
    private const int SourcePortOffset = 0;
    private const int DestinationPortOffset = SourcePortOffset + sizeof(ushort);
    private const int LengthOffset = DestinationPortOffset + sizeof(ushort);
    private const int ChecksumOffset = LengthOffset + sizeof(ushort);
    /// <summary>A zero checksum field means the sender did not compute one (allowed over IPv4 only).</summary>
    private const ushort NoChecksum = 0;
    /// <summary>A computed checksum of zero is sent as all ones, its ones'-complement equivalent (RFC 768).</summary>
    private const ushort ZeroChecksumEncoding = 0xFFFF;

    /// <summary>Header plus payload: the value of the length field.</summary>
    public int Length => HeaderLength + Payload.Length;

    /// <summary>
    /// Encodes the datagram with its checksum. The addresses are not part of the datagram but are covered through
    /// the pseudo-header, so a datagram misdelivered by IP is detected.
    /// </summary>
    /// <param name="source">Our address.</param>
    /// <param name="destination">The peer's address.</param>
    /// <exception cref="ArgumentException">The datagram exceeds the 16-bit length field, or the addresses mix IP families.</exception>
    public byte[] Serialize(IPAddress source, IPAddress destination)
    {
        if (Length > ushort.MaxValue) throw new ArgumentException(UdpMessages.DatagramTooLarge);
        var bytes = new byte[Length];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(SourcePortOffset), SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(DestinationPortOffset), DestinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(LengthOffset), (ushort)Length);
        Payload.Span.CopyTo(bytes.AsSpan(HeaderLength));
        var checksum = InternetChecksum.Compute(PseudoHeader.Prepend(source, destination, (byte)IPv4ProtocolNumber.Udp, bytes));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(ChecksumOffset), checksum == NoChecksum ? ZeroChecksumEncoding : checksum);
        return bytes;
    }

    /// <summary>
    /// Decodes and validates an IP payload as a UDP datagram. The length field must fit the bytes received; bytes
    /// beyond it (link padding) are ignored. A zero checksum is accepted over IPv4, where it means "not computed",
    /// but not over IPv6, which requires one (RFC 8200 8.1).
    /// </summary>
    /// <param name="source">Source address from the IP header.</param>
    /// <param name="destination">Destination address from the IP header.</param>
    /// <param name="bytes">The IP payload.</param>
    /// <exception cref="ArgumentException">The bytes are not a valid UDP datagram for these addresses.</exception>
    public static UdpDatagram Parse(IPAddress source, IPAddress destination, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderLength) throw new ArgumentException(UdpMessages.InvalidLength);
        var length = BinaryPrimitives.ReadUInt16BigEndian(bytes[LengthOffset..]);
        if (length < HeaderLength || length > bytes.Length) throw new ArgumentException(UdpMessages.InvalidLength);
        var datagram = bytes[..length];
        var checksum = BinaryPrimitives.ReadUInt16BigEndian(datagram[ChecksumOffset..]);
        if (checksum == NoChecksum && source.AddressFamily == AddressFamily.InterNetworkV6)
            throw new ArgumentException(UdpMessages.ChecksumRequired);
        if (checksum != NoChecksum &&
            !InternetChecksum.IsValid(PseudoHeader.Prepend(source, destination, (byte)IPv4ProtocolNumber.Udp, datagram)))
            throw new ArgumentException(UdpMessages.InvalidChecksum);
        return new(
            SourcePort: BinaryPrimitives.ReadUInt16BigEndian(datagram[SourcePortOffset..]),
            DestinationPort: BinaryPrimitives.ReadUInt16BigEndian(datagram[DestinationPortOffset..]),
            Payload: datagram[HeaderLength..].ToArray());
    }

    /// <summary>Reads the ports from the first 8 bytes of a datagram quoted in an ICMP error, which carry no checksum guarantee.</summary>
    internal static (ushort SourcePort, ushort DestinationPort) ReadPorts(ReadOnlySpan<byte> header) =>
        (BinaryPrimitives.ReadUInt16BigEndian(header[SourcePortOffset..]),
         BinaryPrimitives.ReadUInt16BigEndian(header[DestinationPortOffset..]));
}
