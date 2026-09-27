using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>
/// While the peer's window is shut, probes it with backoff so a lost window update cannot stall the
/// connection forever (RFC 9293 3.8.6.1), and gives up on a peer that never answers.
/// </summary>
/// <remarks>
/// When the peer advertises a zero window, we must stop sending. The window update that reopens it is a bare
/// ACK, which TCP never retransmits, so if it is lost both sides wait forever. The persist timer breaks
/// that deadlock by sending a small probe that forces the peer to re-announce its window. Delays start at the
/// RTO and double up to 60 seconds. After eight unanswered probes the <see cref="TcpConnection"/> gives up.
/// This class keeps only the schedule; the connection chooses and sends the probe.
/// </remarks>
internal sealed class PersistTimer
{
    private const double InitialDelaySeconds = 1;
    private const double MaximumDelaySeconds = 60;
    private const double BackoffMultiplier = 2;
    private const int MaximumUnansweredProbes = 8;

    private DateTimeOffset _dueAt;
    private double _delaySeconds = InitialDelaySeconds;
    private int _unansweredProbes;

    /// <summary>The peer has ignored so many probes that it is presumed dead.</summary>
    public bool ProbesExhausted => _unansweredProbes >= MaximumUnansweredProbes;

    /// <summary>Whether the next probe should be sent at <paramref name="now"/>.</summary>
    public bool IsDue(DateTimeOffset now) => now >= _dueAt;

    /// <summary>Sets the next probe time without changing the backoff delay.</summary>
    public void Schedule(DateTimeOffset now, double seconds) => _dueAt = now.AddSeconds(seconds);

    /// <summary>Any acceptable ACK shows the peer is alive, so the unanswered-probe count restarts.</summary>
    public void PeerResponded() => _unansweredProbes = 0;

    /// <summary>The peer's window is non-zero: reset the backoff so a future closure starts probing promptly.</summary>
    public void WindowOpened(DateTimeOffset now, double retransmissionTimeout)
    {
        _delaySeconds = InitialDelaySeconds;
        Schedule(now, retransmissionTimeout);
    }

    /// <summary>The peer's window just dropped to zero: the first probe goes out one RTO from now.</summary>
    public void WindowClosed(DateTimeOffset now, double retransmissionTimeout)
    {
        _delaySeconds = retransmissionTimeout;
        Schedule(now, retransmissionTimeout);
    }

    /// <summary>Counts a probe as unanswered until an ACK arrives, and doubles the delay before the next one.</summary>
    public void ProbeSent(DateTimeOffset now)
    {
        _unansweredProbes++;
        _delaySeconds = Math.Min(MaximumDelaySeconds, _delaySeconds * BackoffMultiplier);
        Schedule(now, _delaySeconds);
    }
}
