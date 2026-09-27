using System.Net;
using TCP.L3.Network.IPv4;

namespace TCP.L3.Network;

/// <summary>What an <see cref="IPv4Host"/> needs from the link layer beneath it.</summary>
/// <remarks>
/// This is the seam between L3 and L2. The IP host decides where a datagram goes; the link resolves on-link
/// addresses to hardware addresses (for Ethernet, through ARP) and frames the datagram. Keeping the interface
/// this small lets tests run IP over a fake link. <see cref="Stack.EthernetStack"/> is the real implementation.
/// </remarks>
public interface IIPv4Link
{
    /// <summary>False while the link cannot carry traffic, such as during an address-conflict probe.</summary>
    bool IsReady { get; }

    /// <summary>Send a complete datagram to the link broadcast address.</summary>
    void SendBroadcast(IPv4Packet packet);

    /// <summary>
    /// Send a complete datagram to an on-link neighbor. The link resolves the neighbor's
    /// hardware address, then passes the datagram through <see cref="IPv4Host.FragmentForTransmit"/>.
    /// </summary>
    void SendToNeighbor(IPAddress nextHop, IPv4Packet packet);
}
