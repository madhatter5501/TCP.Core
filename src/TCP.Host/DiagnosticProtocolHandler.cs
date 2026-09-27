using TCP.L3.Network.IPv4;

namespace TCP.Host;

internal sealed class DiagnosticProtocolHandler : IIPv4ProtocolHandler
{
    public int IcmpCount { get; private set; }
    public int TcpCount { get; private set; }
    public int UdpCount { get; private set; }
    public int UnknownCount { get; private set; }

    public void HandleIcmp(in IPv4Packet packet) => IcmpCount++;
    public void HandleTcp(in IPv4Packet packet) => TcpCount++;
    public void HandleUdp(in IPv4Packet packet) => UdpCount++;
    public void HandleUnknown(in IPv4Packet packet) => UnknownCount++;
}