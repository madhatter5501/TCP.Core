using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Congestion;

/// <summary>
/// The congestion window (cwnd) and slow-start threshold (ssthresh), and how they react to acknowledgments,
/// losses, ECN marks, timeouts and idleness. Subclasses supply the growth and reduction rules.
/// </summary>
/// <remarks>
/// <para>
/// Flow control (the peer's window) protects the receiver. Congestion control protects the network in between:
/// the sender may have at most min(cwnd, peer window) bytes in flight. Below ssthresh the window grows
/// exponentially (slow start); above it, the algorithm's congestion avoidance takes over.
/// </para>
/// <para>
/// The controller only does arithmetic. Deciding that a loss happened, and what to retransmit, is loss recovery's
/// job in <see cref="TcpConnection"/>, which calls <see cref="OnCongestionEvent"/> once per loss episode. That split
/// lets any algorithm here work with SACK, RACK-TLP, NewReno recovery and ECN alike.
/// </para>
/// </remarks>
internal abstract class CongestionController
{
    private const int MinimumWindowSegments = 2;
    private const int InitialWindowBytesPerSegment = 1460; // RFC 6928: IW = min(10 x MSS, max(2 x MSS, 14600)).
    private const int SlowStartAckLimitSegments = 2; // RFC 3465 L = 2 x SMSS.

    /// <summary>
    /// cwnd and ssthresh from before the first reduction since new data was last acknowledged, kept so
    /// <see cref="UndoReduction"/> can restore them. Cleared when new data is acknowledged.
    /// </summary>
    private (double Window, double Threshold)? _beforeReduction;

    /// <summary>The congestion window in bytes.</summary>
    public double Window { get; protected set; }

    /// <summary>The slow-start threshold in bytes; effectively unbounded until the first congestion event.</summary>
    public double SlowStartThreshold { get; protected set; } = int.MaxValue;

    /// <summary>Whether the window is still in slow start.</summary>
    public bool InSlowStart => Window < SlowStartThreshold;

    /// <summary>Creates the controller for <paramref name="algorithm"/>.</summary>
    public static CongestionController Create(TcpCongestionAlgorithm algorithm) => algorithm switch
    {
        TcpCongestionAlgorithm.Cubic => new CubicCongestionController(),
        _ => new NewRenoCongestionController()
    };

    /// <summary>The initial window for <paramref name="segments"/> segments of <paramref name="mss"/> bytes (RFC 6928 2, generalized).</summary>
    public static double InitialWindow(int mss, int segments)
    {
        segments = Math.Max(1, segments);
        return Math.Min(segments * mss, Math.Max(MinimumWindowSegments * mss, segments * InitialWindowBytesPerSegment));
    }

    /// <summary>Sets the initial window once the handshake has fixed the MSS.</summary>
    public void Start(int mss, int initialWindowSegments) => Window = InitialWindow(mss, initialWindowSegments);

    /// <summary>
    /// New data was acknowledged outside loss recovery: grow the window. Slow start adds the bytes acknowledged, up to
    /// two segments per ACK (appropriate byte counting, RFC 3465), and congestion avoidance is the algorithm's own.
    /// </summary>
    /// <param name="bytesAcknowledged">How far SND.UNA moved.</param>
    /// <param name="mss">Current maximum segment size.</param>
    /// <param name="now">Current time, for time-based algorithms.</param>
    /// <param name="smoothedRtt">SRTT, or null before the first sample.</param>
    public void OnAcknowledged(uint bytesAcknowledged, int mss, DateTimeOffset now, TimeSpan? smoothedRtt)
    {
        Forget();
        if (!InSlowStart)
        {
            AvoidCongestion(bytesAcknowledged, mss, now, smoothedRtt);
            return;
        }
        var increase = Math.Min(bytesAcknowledged, SlowStartAckLimitSegments * mss);
        Window = Math.Min(Window + increase, Math.Max(Window, SlowStartThreshold));
    }

    /// <summary>
    /// One loss episode, ECN echo or tail-loss repair (RFC 5681 3.2, RFC 3168 6.1.2): lower ssthresh and cut cwnd to it.
    /// Callers invoke this at most once per window of data.
    /// </summary>
    /// <param name="flightSize">Bytes outstanding when the congestion was detected.</param>
    /// <param name="mss">Current maximum segment size.</param>
    /// <param name="now">Current time.</param>
    public void OnCongestionEvent(uint flightSize, int mss, DateTimeOffset now)
    {
        Remember();
        SlowStartThreshold = Math.Max(ReducedWindow(flightSize, mss, now), MinimumWindowSegments * mss);
        Window = SlowStartThreshold;
    }

    /// <summary>A retransmission timer expired: lower ssthresh as for a loss, then restart from a one-segment window (RFC 5681 3.1).</summary>
    public void OnRetransmissionTimeout(uint flightSize, int mss, DateTimeOffset now)
    {
        Remember();
        SlowStartThreshold = Math.Max(ReducedWindow(flightSize, mss, now), MinimumWindowSegments * mss);
        Window = mss;
    }

    /// <summary>
    /// The connection sat idle for longer than an RTO, so the ACK clock is lost: shrink cwnd to at most the initial
    /// window before sending again (RFC 5681 4.1).
    /// </summary>
    public void OnIdleRestart(int mss, int initialWindowSegments)
    {
        Window = Math.Min(Window, InitialWindow(mss, initialWindowSegments));
        OnRestart();
    }

    /// <summary>
    /// The last reduction turned out to be spurious (a timestamp or D-SACK showed the original arrived), so restore
    /// cwnd and ssthresh to their earlier values (RFC 3522, RFC 4015). Only the most recent reduction can be undone.
    /// </summary>
    /// <returns>Whether there was a reduction to undo.</returns>
    public bool UndoReduction()
    {
        if (_beforeReduction is not { } before) return false;
        (Window, SlowStartThreshold) = before;
        _beforeReduction = null;
        OnUndo();
        return true;
    }

    /// <summary>Congestion avoidance growth for one ACK.</summary>
    protected abstract void AvoidCongestion(uint bytesAcknowledged, int mss, DateTimeOffset now, TimeSpan? smoothedRtt);

    /// <summary>The new ssthresh after congestion, before the two-segment floor is applied. Also updates algorithm state.</summary>
    protected abstract double ReducedWindow(uint flightSize, int mss, DateTimeOffset now);

    /// <summary>Hook for algorithms that keep an epoch to reset when sending restarts after idleness.</summary>
    protected virtual void OnRestart() { }

    /// <summary>Hook for algorithms to snapshot their own state before a reduction that might be undone.</summary>
    protected virtual void OnRemember() { }

    /// <summary>Hook for algorithms to restore their own state along with cwnd and ssthresh.</summary>
    protected virtual void OnUndo() { }

    /// <summary>Snapshots the state before the first of a run of reductions, so an undo returns to where congestion began.</summary>
    private void Remember()
    {
        if (_beforeReduction is not null) return;
        _beforeReduction = (Window, SlowStartThreshold);
        OnRemember();
    }

    /// <summary>The window grew again, so the last reduction stands and can no longer be undone.</summary>
    private void Forget() => _beforeReduction = null;
}
