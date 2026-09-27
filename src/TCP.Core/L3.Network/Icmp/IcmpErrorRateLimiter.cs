namespace TCP.L3.Network.Icmp;

/// <summary>Caps outgoing ICMP error messages per second (RFC 1812 4.3.2.8, RFC 1122 3.2.2).</summary>
/// <remarks>
/// Every malformed or undeliverable datagram could earn an ICMP error. Without a cap, a flood of bad traffic
/// would be answered with an equal flood, wasting bandwidth or reflecting an attack onto a spoofed source.
/// </remarks>
internal sealed class IcmpErrorRateLimiter
{
    private const int MaximumPerInterval = 10;
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    private DateTimeOffset _intervalStart;
    private int _sent;

    /// <summary>Uses one error from the current one-second budget, starting a new interval when the last has elapsed.</summary>
    /// <returns>True when an error may be sent now.</returns>
    public bool TryAcquire(DateTimeOffset now)
    {
        if (now - _intervalStart >= Interval)
        {
            _intervalStart = now;
            _sent = 0;
        }
        return _sent++ < MaximumPerInterval;
    }
}
