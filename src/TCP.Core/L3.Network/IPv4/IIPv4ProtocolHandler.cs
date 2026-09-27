namespace TCP.L3.Network.IPv4;

/// <summary>
/// Visitor for datagrams by protocol, used with <see cref="IPv4ProtocolDispatcher"/>. Diagnostic tools implement
/// it to inspect captured traffic; the live stack registers handlers with <see cref="IPv4Host.RegisterProtocol"/> instead.
/// </summary>
public interface IIPv4ProtocolHandler
{
    /// <summary>Called for protocol 1.</summary>
    void HandleIcmp(in IPv4Packet packet);
    /// <summary>Called for protocol 6.</summary>
    void HandleTcp(in IPv4Packet packet);
    /// <summary>Called for protocol 17.</summary>
    void HandleUdp(in IPv4Packet packet);
    /// <summary>Called for any other protocol number.</summary>
    void HandleUnknown(in IPv4Packet packet);
}