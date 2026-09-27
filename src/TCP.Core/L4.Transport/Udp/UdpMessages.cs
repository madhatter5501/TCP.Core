namespace TCP.L4.Transport.Udp;

/// <summary>Stable diagnostics for UDP validation and API misuse, so tests and tools can match them.</summary>
internal static class UdpMessages
{
    public const string DatagramTooLarge = "UDP datagram exceeds the 16-bit length field.";
    public const string PayloadTooLarge = "UDP payload exceeds the 65,507 bytes one IPv4 datagram can carry.";
    public const string InvalidLength = "Invalid UDP length.";
    public const string InvalidChecksum = "Invalid UDP checksum.";
    public const string ChecksumRequired = "UDP over IPv6 requires a checksum.";
    public const string PortInUse = "UDP port is already bound.";
    public const string EphemeralPortsExhausted = "No ephemeral UDP port is available.";
    public const string InvalidDestination = "A destination address and non-zero port are required.";
    public const string BroadcastNotEnabled = "Sending to a broadcast or multicast address requires EnableBroadcast.";
    public const string NotConnected = "Send without a destination requires Connect first.";
    public const string NetworkErrorFormat = "ICMP type {0}, code {1}";
}
