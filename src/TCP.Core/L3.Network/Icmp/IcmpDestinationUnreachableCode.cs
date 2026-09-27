namespace TCP.L3.Network.Icmp;

/// <summary>Destination Unreachable code values used by the IPv4 host.</summary>
public enum IcmpDestinationUnreachableCode : byte
{
    /// <summary>No route to the destination network.</summary>
    NetworkUnreachable = 0,
    /// <summary>The network is reachable but the host did not answer.</summary>
    HostUnreachable = 1,
    /// <summary>The destination host has no handler for the datagram's protocol.</summary>
    ProtocolUnreachable = 2,
    /// <summary>The destination transport has nothing listening on that port.</summary>
    PortUnreachable = 3,
    /// <summary>Too big for the next link and Don't Fragment was set. The next-hop MTU drives path MTU discovery (RFC 1191).</summary>
    FragmentationNeeded = 4,
    /// <summary>A source-routed datagram could not follow its route, or source routes are refused.</summary>
    SourceRouteFailed = 5
}
