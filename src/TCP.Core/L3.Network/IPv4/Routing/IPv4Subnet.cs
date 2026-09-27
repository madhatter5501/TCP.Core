using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace TCP.L3.Network.IPv4.Routing;

/// <summary>The connected route and address rules for a single IPv4 subnet.</summary>
/// <remarks>
/// An address plus mask define the network this interface sits on, such as 192.0.2.0/24. From that the stack
/// decides:
/// <list type="bullet">
/// <item>which destinations are on-link, reached directly through ARP rather than through a gateway;</item>
/// <item>which destinations are broadcasts;</item>
/// <item>which source addresses are plausible, since special-purpose addresses may never appear as a source (RFC 1122 3.2.1.3).</item>
/// </list>
/// </remarks>
public sealed class IPv4Subnet
{
    /// <summary>/31 point-to-point links (RFC 3021) and /32 host routes have no network or broadcast address.</summary>
    private const int PointToPointPrefixLength = 31;
    private const int FirstOctetShift = 24;
    private const uint ThisNetworkFirstOctet = 0;
    private const uint LoopbackFirstOctet = 127;
    private const uint FirstMulticastOctet = 224;

    private readonly uint _network;
    private readonly uint _mask;

    /// <summary>Creates the subnet containing <paramref name="address"/>.</summary>
    /// <param name="address">Any address in the subnet; host bits are discarded.</param>
    /// <param name="mask">The subnet mask, such as 255.255.255.0.</param>
    /// <exception cref="ArgumentException">The mask is not contiguous, or an address is not IPv4.</exception>
    public IPv4Subnet(IPAddress address, IPAddress mask)
    {
        _mask = Read(mask);
        var hostMask = ~_mask;
        if ((hostMask & unchecked(hostMask + 1)) != 0)
            throw new ArgumentException("The IPv4 subnet mask must be contiguous.", nameof(mask));
        _network = Read(address) & _mask;
    }

    /// <summary>Number of network bits: the "/24" in CIDR notation. Longer prefixes are more specific routes.</summary>
    public int PrefixLength => BitOperations.PopCount(_mask);

    /// <summary>The directed broadcast address as a number: all host bits set.</summary>
    private uint BroadcastValue => _network | ~_mask;

    /// <summary>Subnets of /30 and larger set aside the all-zeros and all-ones host addresses.</summary>
    private bool ReservesNetworkAndBroadcastAddresses => PrefixLength < PointToPointPrefixLength;

    /// <summary>Whether <paramref name="address"/> is the limited broadcast (255.255.255.255) or this subnet's directed broadcast.</summary>
    public bool IsBroadcast(IPAddress address) =>
        address.Equals(IPAddress.Broadcast) || (ReservesNetworkAndBroadcastAddresses && address.Equals(ToAddress(BroadcastValue)));

    /// <summary>Whether <paramref name="address"/> lies in this subnet, and so is reachable without a gateway.</summary>
    public bool Contains(IPAddress address) => (Read(address) & _mask) == _network;

    /// <summary>
    /// Whether <paramref name="address"/> may appear as a datagram's source: not in 0/8, 127/8 or the multicast and
    /// reserved range, and, within this subnet, not its network or broadcast address.
    /// </summary>
    public bool IsValidSource(IPAddress address)
    {
        var value = Read(address);
        if (IsSpecialPurpose(value)) return false;
        if (ReservesNetworkAndBroadcastAddresses && Contains(address)) return value != _network && value != BroadcastValue;
        return true;
    }

    /// <summary>
    /// The on-link next hop for <paramref name="destination"/>, which is the destination itself when it is a
    /// usable address in this subnet.
    /// </summary>
    /// <remarks>
    /// Only a connected route is configured here. Do not invent a gateway from the source MAC of an incoming
    /// packet from a remote network.
    /// </remarks>
    public bool TryGetNextHop(IPAddress destination, out IPAddress nextHop)
    {
        nextHop = destination;
        return IsValidSource(destination) && Contains(destination);
    }

    /// <summary>"This network" (0/8), loopback (127/8), and multicast or reserved (224/3) addresses.</summary>
    private static bool IsSpecialPurpose(uint value) =>
        (value >> FirstOctetShift) is ThisNetworkFirstOctet or LoopbackFirstOctet or >= FirstMulticastOctet;

    /// <summary>The address as a 32-bit number, for mask arithmetic.</summary>
    /// <exception cref="ArgumentException">Not an IPv4 address.</exception>
    private static uint Read(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("An IPv4 address is required.", nameof(address));
        return BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
    }

    /// <summary>The inverse of <see cref="Read"/>: a 32-bit number back to an address.</summary>
    private static IPAddress ToAddress(uint value)
    {
        var bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }
}
