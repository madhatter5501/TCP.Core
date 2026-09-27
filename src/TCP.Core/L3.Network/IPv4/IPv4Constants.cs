namespace TCP.L3.Network.IPv4;

/// <summary>IPv4 limits and host defaults shared across layers. Wire-format offsets live on <see cref="IPv4Packet"/>.</summary>
public static class IPv4Constants
{
    /// <summary>Smallest MTU every IPv4 link must support (RFC 791).</summary>
    public const int MinimumMtu = 68;

    /// <summary>Default link MTU, matching standard Ethernet.</summary>
    public const int DefaultMtu = 1500;

    /// <summary>
    /// Largest datagram every IPv4 host must accept (RFC 791, RFC 1122 EMTU_R). Also the conservative
    /// send size for destinations beyond the connected subnet.
    /// </summary>
    public const int MinimumReassemblyLength = 576;

    /// <summary>Default time-to-live for locally originated datagrams (RFC 1700 assigned value).</summary>
    public const byte DefaultTimeToLive = 64;

    /// <summary>
    /// Assumed maximum datagram lifetime in the network. Bounds identifier reuse (RFC 6864) and
    /// matches the TCP maximum segment lifetime (RFC 9293).
    /// </summary>
    public static readonly TimeSpan MaximumDatagramLifetime = TimeSpan.FromMinutes(2);
}
