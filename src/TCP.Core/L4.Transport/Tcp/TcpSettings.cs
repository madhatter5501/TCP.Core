using TCP.L4.Transport.Tcp.Congestion;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// Host-wide TCP policy: which extensions to offer and the timers of the optional behaviors. Pass one to
/// <see cref="TcpHost"/>; every connection it creates starts from these values.
/// </summary>
/// <remarks>
/// Negotiated extensions (window scaling, timestamps, SACK, ECN, Fast Open, user timeout) only take effect when the
/// peer also offers them on its SYN, so enabling one never breaks a peer that lacks it. The defaults follow current
/// practice: every negotiated extension offered, delayed ACKs on, CUBIC congestion control and a ten-segment
/// initial window, while keep-alive stays off as RFC 1122 4.2.3.6 requires.
/// </remarks>
public sealed record TcpSettings
{
    /// <summary>Settings used when a <see cref="TcpHost"/> is created without any.</summary>
    public static TcpSettings Default { get; } = new();

    /// <summary>Acknowledge every second full-sized segment, or after <see cref="DelayedAckTimeout"/>, instead of every segment (RFC 1122 4.2.3.2).</summary>
    public bool DelayedAcknowledgments { get; init; } = true;

    /// <summary>Longest an acknowledgment may be delayed. RFC 9293 3.8.6.3 caps it at 500 ms; 200 ms is common practice.</summary>
    public TimeSpan DelayedAckTimeout { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>Offer window scaling (RFC 7323 2) so receive windows can exceed 64 KiB.</summary>
    public bool WindowScaling { get; init; } = true;

    /// <summary>Offer timestamps (RFC 7323 3-5) for round-trip measurement and protection against wrapped sequence numbers.</summary>
    public bool Timestamps { get; init; } = true;

    /// <summary>Offer selective acknowledgments (RFC 2018), which let loss recovery repair several holes per round trip.</summary>
    public bool SelectiveAcknowledgments { get; init; } = true;

    /// <summary>Offer Explicit Congestion Notification (RFC 3168), so routers can signal congestion without dropping packets.</summary>
    public bool ExplicitCongestionNotification { get; init; } = true;

    /// <summary>The algorithm that sizes the congestion window.</summary>
    public TcpCongestionAlgorithm CongestionControl { get; init; } = TcpCongestionAlgorithm.Cubic;

    /// <summary>
    /// Initial congestion window in segments. The window is min(N x MSS, max(2 x MSS, N x 1460 bytes)); RFC 6928
    /// allows 10, RFC 3390 used 4 and RFC 5681 2. Values below 1 are treated as 1.
    /// </summary>
    public int InitialWindowSegments { get; init; } = 10;

    /// <summary>Use RACK-TLP time-based loss detection and tail loss probes (RFC 8985) when the peer supports SACK.</summary>
    public bool RecentAcknowledgment { get; init; } = true;

    /// <summary>Answer SYNs statelessly with SYN cookies (RFC 4987 3.6) once a listener's backlog is full.</summary>
    public bool SynCookies { get; init; } = true;

    /// <summary>Accept data on SYN with a valid TCP Fast Open cookie on listeners, and use cached cookies on active opens (RFC 7413).</summary>
    public bool FastOpen { get; init; } = true;

    /// <summary>Whether new connections send keep-alive probes when idle (RFC 1122 4.2.3.6). Off by default, as that RFC requires.</summary>
    public bool KeepAlive { get; init; }

    /// <summary>Idle time before the first keep-alive probe. RFC 1122 requires a default of at least two hours.</summary>
    public TimeSpan KeepAliveIdle { get; init; } = TimeSpan.FromHours(2);

    /// <summary>Interval between unanswered keep-alive probes.</summary>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(75);

    /// <summary>Unanswered keep-alive probes before the connection is declared dead.</summary>
    public int KeepAliveProbes { get; init; } = 9;

    /// <summary>
    /// User timeout for new connections (RFC 5482, RFC 9293 3.8.3): how long sent data may stay unacknowledged before
    /// the connection is aborted. Null leaves only the retransmission limit in force. When set it is also advertised.
    /// </summary>
    public TimeSpan? UserTimeout { get; init; }

    /// <summary>Adopt a longer user timeout advertised by the peer, within <see cref="UserTimeoutLimits"/> (RFC 5482 3.1).</summary>
    public bool AcceptPeerUserTimeout { get; init; }

    /// <summary>Bounds on a user timeout adopted from the peer (RFC 5482 L_LIMIT and U_LIMIT).</summary>
    public (TimeSpan Lower, TimeSpan Upper) UserTimeoutLimits { get; init; } = (TimeSpan.FromSeconds(100), TimeSpan.FromHours(1));

    /// <summary>
    /// Detect path MTU black holes: after repeated timeouts of full-sized segments, retry with smaller ones
    /// (RFC 4821 packetization-layer path MTU discovery, as RFC 2923 recommends).
    /// </summary>
    public bool BlackHoleDetection { get; init; } = true;

    /// <summary>How long a lowered path MTU is kept before trying the larger size again (RFC 1191 6.3 suggests 10 minutes).</summary>
    public TimeSpan PathMtuRaiseInterval { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Checks the values are usable.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A timer or count is out of range.</exception>
    internal void Validate()
    {
        if (DelayedAckTimeout <= TimeSpan.Zero || DelayedAckTimeout > TcpConnection.MaximumDelayedAckTimeout)
            throw new ArgumentOutOfRangeException(nameof(DelayedAckTimeout));
        if (KeepAliveIdle <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(KeepAliveIdle));
        if (KeepAliveInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(KeepAliveInterval));
        if (KeepAliveProbes < 1) throw new ArgumentOutOfRangeException(nameof(KeepAliveProbes));
        if (UserTimeout is { } timeout && timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(UserTimeout));
        if (UserTimeoutLimits.Lower <= TimeSpan.Zero || UserTimeoutLimits.Upper < UserTimeoutLimits.Lower)
            throw new ArgumentOutOfRangeException(nameof(UserTimeoutLimits));
        if (PathMtuRaiseInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(PathMtuRaiseInterval));
    }
}
