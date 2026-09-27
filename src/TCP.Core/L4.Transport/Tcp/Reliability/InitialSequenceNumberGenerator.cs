using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using TCP.L3.Network.IPv4;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>
/// Initial sequence numbers per RFC 6528: a 4-microsecond clock plus a keyed hash of the connection
/// four-tuple, so successive connections advance while off-path attackers cannot predict them.
/// </summary>
/// <remarks>
/// The ISN is the first sequence number of each direction. If it were predictable, an attacker who cannot see
/// the traffic could forge segments that land inside the window. If it were purely random, a new connection on the
/// same port pair could reuse sequence numbers a delayed segment from the old connection still carries.
/// Keying the hash per four-tuple and adding a clock satisfies both. <see cref="TcpHost"/> draws one ISN for each
/// connection it creates.
/// </remarks>
/// <param name="time">Clock source; tests substitute a fake one to control the ISN.</param>
internal sealed class InitialSequenceNumberGenerator(TimeProvider time)
{
    private const int SecretBytes = 32;
    private const long ClockTickLength = TimeSpan.TicksPerMicrosecond * 4;
    private const int LocalAddressOffset = 0;
    private const int RemoteAddressOffset = LocalAddressOffset + IPv4Packet.IPv4AddressLength;
    private const int LocalPortOffset = RemoteAddressOffset + IPv4Packet.IPv4AddressLength;
    private const int RemotePortOffset = LocalPortOffset + sizeof(ushort);
    private const int FourTupleLength = RemotePortOffset + sizeof(ushort);
    private const byte TimestampLabel = 0x54; // Separates timestamp offsets from ISNs under the same key.

    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(SecretBytes);

    /// <summary>
    /// ISN = M + F(localip, localport, remoteip, remoteport, secretkey), where M is the clock and F is
    /// HMAC-SHA256 keyed with a per-host random secret.
    /// </summary>
    /// <param name="localAddress">Our IPv4 address.</param>
    /// <param name="connection">The ports and remote address of the connection being opened.</param>
    public uint Next(IPAddress localAddress, ConnectionKey connection)
    {
        var hash = HMACSHA256.HashData(_secret, FourTuple(localAddress, connection));
        return unchecked(BinaryPrimitives.ReadUInt32BigEndian(hash) + (uint)(time.GetUtcNow().Ticks / ClockTickLength));
    }

    /// <summary>
    /// A per-connection offset for the timestamp clock (RFC 7323 5.4 and 7.1), so TSval values reveal neither host
    /// uptime nor a relation between connections. It is a keyed hash of the four-tuple, so a SYN-cookie connection
    /// rebuilt later computes the same offset its SYN-ACK used.
    /// </summary>
    public uint TimestampOffset(IPAddress localAddress, ConnectionKey connection)
    {
        byte[] input = [.. FourTuple(localAddress, connection), TimestampLabel];
        return BinaryPrimitives.ReadUInt32BigEndian(HMACSHA256.HashData(_secret, input));
    }

    /// <summary>Serializes the four-tuple in network byte order as the HMAC input.</summary>
    private static byte[] FourTuple(IPAddress localAddress, ConnectionKey connection)
    {
        var tuple = new byte[FourTupleLength];
        localAddress.GetAddressBytes().CopyTo(tuple, LocalAddressOffset);
        connection.RemoteAddress.GetAddressBytes().CopyTo(tuple, RemoteAddressOffset);
        BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(LocalPortOffset), connection.LocalPort);
        BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(RemotePortOffset), connection.RemotePort);
        return tuple;
    }
}
