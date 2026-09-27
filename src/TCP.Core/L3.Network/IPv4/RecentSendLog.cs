using System.Net;

namespace TCP.L3.Network.IPv4;

/// <summary>
/// Remembers recently sent unicast datagrams by the fields an ICMP error quotes: destination, protocol and
/// Identification.
/// </summary>
/// <remarks>
/// ICMP errors are easy to forge and can reset connections or shrink the path MTU. <see cref="IPv4Host"/> only
/// believes an error that quotes a datagram it really sent within the last datagram lifetime (RFC 5927 4.1).
/// The log is bounded; when full, the oldest entry is forgotten.
/// </remarks>
internal sealed class RecentSendLog
{
    private const int Capacity = 1024;

    private readonly Dictionary<(IPAddress Destination, byte Protocol, ushort Identification), DateTimeOffset> _expiresAt = [];

    /// <summary>Notes that <paramref name="packet"/> was just sent.</summary>
    public void Record(IPv4Packet packet, DateTimeOffset now)
    {
        if (_expiresAt.Count >= Capacity) _expiresAt.Remove(_expiresAt.MinBy(send => send.Value).Key);
        _expiresAt[(packet.DestinationAddress, packet.Protocol, packet.Identification)] = now + IPv4Constants.MaximumDatagramLifetime;
    }

    /// <summary>Whether a datagram with these fields was sent recently enough that an error about it is plausible.</summary>
    public bool Contains(IPAddress destination, byte protocol, ushort identification, DateTimeOffset now) =>
        _expiresAt.TryGetValue((destination, protocol, identification), out var expiresAt) && expiresAt > now;
}
