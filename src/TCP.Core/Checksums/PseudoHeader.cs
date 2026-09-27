using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace TCP.Checksums;

/// <summary>
/// The pseudo-header that TCP and UDP checksums cover in front of the segment: the IP addresses, protocol number
/// and segment length (RFC 9293 3.1 and RFC 768 for IPv4, RFC 8200 8.1 for IPv6).
/// </summary>
/// <remarks>
/// The addresses are not part of the transport header, yet a datagram that IP delivered to the wrong host, or
/// whose addresses were corrupted, must not be accepted. Folding them into the checksum catches that. The
/// pseudo-header is never transmitted; both ends rebuild it from the IP header.
/// </remarks>
public static class PseudoHeader
{
    private const int IPv4AddressLength = 4;
    private const int IPv4SourceOffset = 0;
    private const int IPv4DestinationOffset = IPv4SourceOffset + IPv4AddressLength;
    private const int IPv4ProtocolOffset = IPv4DestinationOffset + IPv4AddressLength + sizeof(byte); // After one zero byte.
    private const int IPv4LengthOffset = IPv4ProtocolOffset + sizeof(byte);
    private const int IPv4Length = IPv4LengthOffset + sizeof(ushort);
    private const int IPv6AddressLength = 16;
    private const int IPv6SourceOffset = 0;
    private const int IPv6DestinationOffset = IPv6SourceOffset + IPv6AddressLength;
    private const int IPv6LengthOffset = IPv6DestinationOffset + IPv6AddressLength;
    private const int IPv6NextHeaderOffset = IPv6LengthOffset + sizeof(uint) + 3; // After three zero bytes.
    private const int IPv6Length = IPv6NextHeaderOffset + sizeof(byte);

    /// <summary>
    /// <paramref name="segment"/> preceded by its pseudo-header: 12 bytes for IPv4 (source, destination, zero, protocol,
    /// 16-bit length) or 40 for IPv6 (source, destination, 32-bit length, three zeros, next header).
    /// </summary>
    /// <param name="source">The sender's address.</param>
    /// <param name="destination">The receiver's address; must be the same family.</param>
    /// <param name="protocol">The IP protocol number, such as 6 for TCP or 17 for UDP.</param>
    /// <param name="segment">The transport header and payload.</param>
    /// <exception cref="ArgumentException">The addresses are not both IPv4 or both IPv6.</exception>
    public static byte[] Prepend(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> segment)
    {
        if (source.AddressFamily != destination.AddressFamily ||
            source.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new ArgumentException("Pseudo-header addresses must both be IPv4 or both be IPv6.");
        return source.AddressFamily == AddressFamily.InterNetwork
            ? PrependIPv4(source, destination, protocol, segment)
            : PrependIPv6(source, destination, protocol, segment);
    }

    private static byte[] PrependIPv4(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> segment)
    {
        var bytes = new byte[IPv4Length + segment.Length];
        source.GetAddressBytes().CopyTo(bytes, IPv4SourceOffset);
        destination.GetAddressBytes().CopyTo(bytes, IPv4DestinationOffset);
        bytes[IPv4ProtocolOffset] = protocol;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(IPv4LengthOffset), (ushort)segment.Length);
        segment.CopyTo(bytes.AsSpan(IPv4Length));
        return bytes;
    }

    private static byte[] PrependIPv6(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> segment)
    {
        var bytes = new byte[IPv6Length + segment.Length];
        source.GetAddressBytes().CopyTo(bytes, IPv6SourceOffset);
        destination.GetAddressBytes().CopyTo(bytes, IPv6DestinationOffset);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(IPv6LengthOffset), (uint)segment.Length);
        bytes[IPv6NextHeaderOffset] = protocol;
        segment.CopyTo(bytes.AsSpan(IPv6Length));
        return bytes;
    }
}
