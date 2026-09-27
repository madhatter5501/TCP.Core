using System.Net;
using System.Net.Sockets;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Arp;

/// <summary>Answers ARP requests for our own address (RFC 826).</summary>
public static class ArpResponder
{
    /// <summary>Creates the reply to a request asking for <paramref name="localProtocolAddress"/>, addressed back to the requester.</summary>
    /// <returns>False when the packet is not a request for our address.</returns>
    /// <exception cref="ArgumentException"><paramref name="localProtocolAddress"/> is not IPv4.</exception>
    public static bool TryCreateReply(
        ArpPacket request,
        IPAddress localProtocolAddress,
        MacAddress localHardwareAddress,
        out ArpPacket reply)
    {
        ArgumentNullException.ThrowIfNull(localProtocolAddress);
        if (localProtocolAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("ARP Ethernet replies require an IPv4 address.", nameof(localProtocolAddress));
        }

        if (request.Operation != ArpOperation.Request ||
            !localProtocolAddress.Equals(request.TargetProtocolAddress))
        {
            reply = default;
            return false;
        }

        reply = ArpPacket.CreateReply(
            localHardwareAddress,
            localProtocolAddress,
            request.SenderHardwareAddress,
            request.SenderProtocolAddress);
        return true;
    }
}
