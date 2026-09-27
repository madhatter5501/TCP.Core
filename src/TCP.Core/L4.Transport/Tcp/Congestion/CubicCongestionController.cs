namespace TCP.L4.Transport.Tcp.Congestion;

/// <summary>CUBIC congestion control (RFC 9438), the default in Linux, Windows and macOS.</summary>
/// <remarks>
/// <para>
/// Reno's one-segment-per-RTT growth takes minutes to refill a large window after a loss. CUBIC instead remembers
/// the window where the loss happened (W_max) and grows along W_cubic(t) = C (t - K)^3 + W_max, where t is time since
/// the reduction and K is when the curve returns to W_max. Growth is fast far below W_max, flat near it (probing
/// cautiously where loss happened last), then accelerates again beyond it. Because growth depends on time rather
/// than on ACK arrivals, flows with different RTTs share a bottleneck more fairly.
/// </para>
/// <para>
/// On short-RTT paths the cubic curve can be slower than Reno, so CUBIC also tracks an estimate of what Reno
/// would have (W_est) and never grows slower than that ("Reno-friendly region", RFC 9438 4.3).
/// </para>
/// <para>Windows are kept in segments here, as in the RFC, and converted to bytes at the boundary.</para>
/// </remarks>
internal sealed class CubicCongestionController : CongestionController
{
    private const double C = 0.4; // Cubic scaling constant, segments / s^3.
    private const double Beta = 0.7; // Multiplicative decrease factor.
    private const double RenoFriendlyAlpha = 3 * (1 - Beta) / (1 + Beta);
    private const double MaximumGrowthFactor = 1.5; // Target is clamped to [cwnd, 1.5 cwnd] (RFC 9438 4.2).
    private static readonly TimeSpan DefaultRtt = TimeSpan.FromMilliseconds(100);

    private double _windowMax; // W_max, segments.
    private double _epochWindow; // cwnd_epoch, segments.
    private double _renoEstimate; // W_est, segments.
    private double _k; // Seconds from the epoch start until W_cubic reaches W_max.
    private DateTimeOffset? _epochStart; // t_epoch.
    /// <summary>The CUBIC curve's state saved alongside the base class's snapshot, restored if the reduction is undone as spurious.</summary>
    private (double WindowMax, DateTimeOffset? EpochStart, double EpochWindow, double RenoEstimate, double K)? _saved;

    /// <summary>
    /// Congestion avoidance for one ACK (RFC 9438 4.2-4.5): aim for W_cubic one RTT ahead, but never below the
    /// Reno-friendly estimate.
    /// </summary>
    protected override void AvoidCongestion(uint bytesAcknowledged, int mss, DateTimeOffset now, TimeSpan? smoothedRtt)
    {
        var window = Window / mss;
        if (_epochStart is null) StartEpoch(window, now);
        var elapsed = (now - _epochStart!.Value).TotalSeconds;
        var rtt = (smoothedRtt ?? DefaultRtt).TotalSeconds;
        var target = Math.Clamp(CubicWindow(elapsed + rtt), window, MaximumGrowthFactor * window);
        var segmentsAcknowledged = (double)bytesAcknowledged / mss;
        var alpha = _renoEstimate >= _windowMax ? 1 : RenoFriendlyAlpha;
        _renoEstimate += alpha * segmentsAcknowledged / window;
        if (CubicWindow(elapsed) < _renoEstimate) window = Math.Max(window, _renoEstimate);
        else window += (target - window) / window * segmentsAcknowledged;
        Window = window * mss;
    }

    /// <summary>
    /// A congestion event (RFC 9438 4.6-4.7): remember W_max, with fast convergence releasing bandwidth when the
    /// window never regained the previous maximum, and cut to beta x cwnd.
    /// </summary>
    protected override double ReducedWindow(uint flightSize, int mss, DateTimeOffset now)
    {
        var window = Window / mss;
        _windowMax = window < _windowMax ? window * (1 + Beta) / 2 : window;
        _epochStart = null;
        return Window * Beta;
    }

    /// <summary>After idleness the curve's time origin is stale, so the next ACK starts a new epoch.</summary>
    protected override void OnRestart() => _epochStart = null;

    /// <summary>Snapshots the curve so a spurious reduction can be undone.</summary>
    protected override void OnRemember() => _saved = (_windowMax, _epochStart, _epochWindow, _renoEstimate, _k);

    /// <summary>Restores the curve that was in force before the undone reduction.</summary>
    protected override void OnUndo()
    {
        if (_saved is { } saved) (_windowMax, _epochStart, _epochWindow, _renoEstimate, _k) = saved;
        _saved = null;
    }

    /// <summary>Begins a growth epoch (RFC 9438 4.2): K is when the curve from the current window returns to W_max.</summary>
    private void StartEpoch(double window, DateTimeOffset now)
    {
        _epochStart = now;
        _epochWindow = window;
        _renoEstimate = window;
        if (_windowMax < window) _windowMax = window;
        _k = Math.Cbrt((_windowMax - _epochWindow) / C);
    }

    /// <summary>W_cubic(t) = C (t - K)^3 + W_max, in segments.</summary>
    private double CubicWindow(double seconds) => C * Math.Pow(seconds - _k, 3) + _windowMax;
}
