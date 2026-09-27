namespace TCP.L3.Network.IPv4;

/// <summary>
/// Values of the IPv4 Protocol field, naming the upper-layer protocol a datagram carries (IANA assigned numbers).
/// <see cref="IPv4Host"/> uses it to deliver each datagram to ICMP or to a registered transport.
/// </summary>
public enum IPv4ProtocolNumber : byte
{
    /// <summary>Internet Control Message Protocol; handled by the host itself.</summary>
    Icmp = 1,
    /// <summary>Transmission Control Protocol: reliable byte streams.</summary>
    Tcp = 6,
    /// <summary>User Datagram Protocol: unreliable datagrams.</summary>
    Udp = 17
}