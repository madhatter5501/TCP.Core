namespace TCP.L4.Transport.Tcp.Congestion;

/// <summary>
/// Reno's window rules (RFC 5681): add about one segment per round trip in congestion avoidance, and halve the
/// data in flight on congestion. Paired with NewReno partial-ACK recovery (RFC 6582) in the connection.
/// </summary>
internal sealed class NewRenoCongestionController : CongestionController
{
    private const double ReductionDivisor = 2;
    private const double MinimumIncrementBytes = 1;

    /// <summary>Byte-counting congestion avoidance (RFC 3465 2.1): cwnd grows by MSS x acked / cwnd, one MSS per window acknowledged.</summary>
    protected override void AvoidCongestion(uint bytesAcknowledged, int mss, DateTimeOffset now, TimeSpan? smoothedRtt) =>
        Window += Math.Max(MinimumIncrementBytes, (double)mss * bytesAcknowledged / Window);

    /// <summary>Half the flight (RFC 5681 equation 4).</summary>
    protected override double ReducedWindow(uint flightSize, int mss, DateTimeOffset now) => flightSize / ReductionDivisor;
}
