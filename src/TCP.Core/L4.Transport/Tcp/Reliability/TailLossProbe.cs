namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>TLP: the tail loss probe timer and episode state (RFC 8985 7).</summary>
/// <remarks>
/// <para>
/// When the last segments of a flight are lost, no later data arrives to reveal the hole, so recovery used to wait
/// for a full retransmission timeout. TLP instead fires a probe timeout (PTO) of about two round trips after the
/// last send: it sends one segment (new data if any, otherwise the last segment again). The ACK or SACK for that
/// probe gives RACK the information to repair the tail with fast recovery instead of a timeout.
/// </para>
/// <para>
/// If the probe was a retransmission and the ACK shows it repaired a genuine loss, congestion control must still
/// react; if a D-SACK shows the original arrived too, there was no loss (RFC 8985 7.4).
/// </para>
/// </remarks>
internal sealed class TailLossProbe
{
    private const int SmoothedRttMultiplier = 2;
    /// <summary>WCDelAckT: the longest a peer is assumed to delay an ACK (RFC 8985 7.2).</summary>
    public static readonly TimeSpan WorstCaseDelayedAck = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan InitialProbeTimeout = TimeSpan.FromSeconds(1);

    private SequenceNumber? _probeEnd; // TLP.end_seq
    private bool _probeWasRetransmission; // TLP.is_retrans

    /// <summary>When the probe timer fires, or null when it is not armed.</summary>
    public DateTimeOffset? Deadline { get; private set; }

    /// <summary>A probe is outstanding; only one may be sent per episode.</summary>
    public bool ProbeOutstanding => _probeEnd is not null;

    /// <summary>
    /// Arms the PTO (RFC 8985 7.2): 2 x SRTT, plus the peer's worst-case delayed-ACK time when only one segment is
    /// outstanding (its ACK may be delayed), and never later than the retransmission timeout would fire.
    /// </summary>
    public void Arm(
        DateTimeOffset now, TimeSpan? smoothedRtt, bool singleSegmentOutstanding, TimeSpan delayedAckAllowance, DateTimeOffset retransmitAt)
    {
        var timeout = smoothedRtt is { } srtt ? srtt * SmoothedRttMultiplier : InitialProbeTimeout;
        if (singleSegmentOutstanding) timeout += delayedAckAllowance;
        var deadline = now + timeout;
        Deadline = deadline < retransmitAt ? deadline : retransmitAt;
    }

    /// <summary>Stops the probe timer.</summary>
    public void Disarm() => Deadline = null;

    /// <summary>Records the probe just sent; the episode lasts until an ACK covers <paramref name="sendNext"/>.</summary>
    public void ProbeSent(SequenceNumber sendNext, bool retransmission)
    {
        Deadline = null;
        _probeEnd = sendNext;
        _probeWasRetransmission = retransmission;
    }

    /// <summary>
    /// Evaluates an ACK against the outstanding probe (RFC 8985 7.4.2), ending the episode when it can.
    /// </summary>
    /// <param name="acknowledgment">The ACK's cumulative acknowledgment.</param>
    /// <param name="duplicateCoversProbe">A D-SACK in the ACK covers the probe, so the original was not lost.</param>
    /// <param name="isPureDuplicate">The ACK advanced nothing and SACKed nothing new.</param>
    /// <returns>True when the probe repaired a real loss, so congestion control must respond.</returns>
    public bool OnAcknowledgment(SequenceNumber acknowledgment, bool duplicateCoversProbe, bool isPureDuplicate)
    {
        if (_probeEnd is not { } end || acknowledgment < end) return false;
        if (!_probeWasRetransmission || duplicateCoversProbe)
        {
            _probeEnd = null;
            return false;
        }
        if (end < acknowledgment)
        {
            _probeEnd = null;
            return true;
        }
        if (isPureDuplicate) _probeEnd = null;
        return false;
    }

    /// <summary>Abandons the episode, as when a retransmission timeout takes over.</summary>
    public void Reset()
    {
        _probeEnd = null;
        Deadline = null;
    }
}
