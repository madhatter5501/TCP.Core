namespace TCP.L3.Network.IPv4;

/// <summary>Routes a datagram to the <see cref="IIPv4ProtocolHandler"/> method for its protocol number.</summary>
public static class IPv4ProtocolDispatcher
{
    /// <summary>Calls exactly one handler method, chosen by <see cref="IPv4Packet.Protocol"/>.</summary>
    public static void Dispatch(in IPv4Packet packet, IIPv4ProtocolHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        switch (packet.Protocol)
        {
            case (byte)IPv4ProtocolNumber.Icmp:
                handler.HandleIcmp(in packet);
                break;
            case (byte)IPv4ProtocolNumber.Tcp:
                handler.HandleTcp(in packet);
                break;
            case (byte)IPv4ProtocolNumber.Udp:
                handler.HandleUdp(in packet);
                break;
            default:
                handler.HandleUnknown(in packet);
                break;
        }
    }
}
