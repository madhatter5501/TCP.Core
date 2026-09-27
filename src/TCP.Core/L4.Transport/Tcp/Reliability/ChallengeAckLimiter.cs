using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>Caps challenge ACKs per second so spoofed segments cannot turn us into an ACK flood (RFC 5961 7).</summary>
/// <remarks>
/// RFC 5961 hardens TCP against blind injection. Instead of trusting an in-window RST or SYN, or an ACK for data
/// never sent, the connection replies with a "challenge ACK" that states its real position; a genuine peer will
/// then send an exact match. An attacker who sprays forged segments would make us send one ACK per forgery, so
/// the <see cref="TcpConnection"/> checks this limiter before each challenge.
/// </remarks>
internal sealed class ChallengeAckLimiter
{
    private const int MaximumPerInterval = 100;
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    private DateTimeOffset _intervalStart;
    private int _sent;

    /// <summary>Uses one challenge from the current one-second budget, starting a new interval when the last has elapsed.</summary>
    /// <returns>True when a challenge ACK may be sent now.</returns>
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
