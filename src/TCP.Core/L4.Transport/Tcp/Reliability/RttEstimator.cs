using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>Derives the retransmission timeout from smoothed round-trip samples (RFC 6298).</summary>
/// <remarks>
/// TCP must guess how long to wait for an ACK before assuming a segment was lost. Too short and it
/// floods the path with needless retransmissions; too long and a loss stalls the stream. This class
/// tracks a smoothed round-trip time (SRTT) and its variation (RTTVAR) from ACK timings, and turns
/// them into RTO = SRTT + 4 x RTTVAR, clamped to [1, 60] seconds. One instance per
/// <see cref="TcpConnection"/>; the connection feeds it samples and reads <see cref="TimeoutSeconds"/>.
/// </remarks>
internal sealed class RttEstimator
{
    private const double InitialTimeoutSeconds = 1;
    private const double MinimumTimeoutSeconds = 1;
    private const double MaximumTimeoutSeconds = 60;
    private const double SynRetransmissionFloorSeconds = 3;
    private const double ClockGranularitySeconds = .001;
    private const double MeanWeight = 1.0 / 8; // alpha
    private const double VariationWeight = 1.0 / 4; // beta
    private const double VariationMultiplier = 4; // K
    private const double InitialVariationDivisor = 2;
    private const double BackoffMultiplier = 2;

    private double _smoothed;
    private double _variation;
    private bool _hasSample;

    /// <summary>The current retransmission timeout (RTO).</summary>
    public double TimeoutSeconds { get; private set; } = InitialTimeoutSeconds;

    /// <summary>The current retransmission timeout as a span.</summary>
    public TimeSpan Timeout => TimeSpan.FromSeconds(TimeoutSeconds);

    /// <summary>SRTT, or null before the first sample.</summary>
    public TimeSpan? SmoothedRtt => _hasSample ? TimeSpan.FromSeconds(_smoothed) : null;

    /// <summary>The smallest round trip measured, the best estimate of the path's propagation delay; null before the first sample.</summary>
    public TimeSpan? MinimumRtt { get; private set; }

    /// <summary>When a retransmission timer started at <paramref name="now"/> should fire.</summary>
    public DateTimeOffset DeadlineFrom(DateTimeOffset now) => now.AddSeconds(TimeoutSeconds);

    /// <summary>
    /// Folds one measured round trip into the estimate and recomputes the timeout (RFC 6298 2.2-2.4).
    /// The caller must only time segments that were never retransmitted (Karn's algorithm).
    /// </summary>
    /// <param name="roundTrip">Time from first sending a segment to receiving its acknowledgment.</param>
    public void AddSample(TimeSpan roundTrip)
    {
        var sample = Math.Max(ClockGranularitySeconds, roundTrip.TotalSeconds);
        if (MinimumRtt is not { } minimum || roundTrip < minimum) MinimumRtt = roundTrip;
        if (_hasSample) Smooth(sample);
        else Initialize(sample);
        var timeout = _smoothed + Math.Max(ClockGranularitySeconds, VariationMultiplier * _variation);
        TimeoutSeconds = Math.Clamp(timeout, MinimumTimeoutSeconds, MaximumTimeoutSeconds);
    }

    /// <summary>The RTO computed from SRTT and RTTVAR without any backoff, restored when a timeout proves spurious.</summary>
    public void ResetBackoff()
    {
        if (!_hasSample) return;
        var timeout = _smoothed + Math.Max(ClockGranularitySeconds, VariationMultiplier * _variation);
        TimeoutSeconds = Math.Clamp(timeout, MinimumTimeoutSeconds, MaximumTimeoutSeconds);
    }

    /// <summary>Doubles the timeout after it expires (RFC 6298 5.5).</summary>
    public void BackOff() => TimeoutSeconds = Math.Min(MaximumTimeoutSeconds, TimeoutSeconds * BackoffMultiplier);

    /// <summary>Once a retransmitted SYN is acknowledged, keep at least the conservative 3-second timeout (RFC 6298 5.7).</summary>
    public void ApplySynRetransmissionFloor() => TimeoutSeconds = Math.Max(SynRetransmissionFloorSeconds, TimeoutSeconds);

    /// <summary>First measurement (RFC 6298 2.2): SRTT = R, RTTVAR = R / 2.</summary>
    private void Initialize(double sample)
    {
        _smoothed = sample;
        _variation = sample / InitialVariationDivisor;
        _hasSample = true;
    }

    /// <summary>
    /// Later measurements (RFC 6298 2.3): exponentially weighted averages, updating RTTVAR before SRTT
    /// so the variation is measured against the previous mean.
    /// </summary>
    private void Smooth(double sample)
    {
        _variation = (1 - VariationWeight) * _variation + VariationWeight * Math.Abs(_smoothed - sample);
        _smoothed = (1 - MeanWeight) * _smoothed + MeanWeight * sample;
    }
}
