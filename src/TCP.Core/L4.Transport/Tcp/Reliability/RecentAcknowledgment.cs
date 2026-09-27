using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>RACK: time-based loss detection (RFC 8985 6).</summary>
/// <remarks>
/// <para>
/// Classic fast retransmit counts duplicate ACKs: three means a loss. That misses losses at the tail of a flight
/// (too few later segments to generate three duplicates), lost retransmissions, and misfires on reordering. RACK
/// asks a time question instead: if a segment sent later than this one has already been delivered, and more than
/// one RTT plus a small reordering window has passed since this one was sent, it is lost.
/// </para>
/// <para>
/// The state is the send time and end sequence of the most recently sent segment known to be delivered, the RTT
/// measured from it, and an adaptive reordering window. The <see cref="TcpConnection"/> feeds it every newly
/// acknowledged or SACKed segment, then asks it to mark losses; segments not yet overdue set a reorder timer.
/// </para>
/// </remarks>
internal sealed class RecentAcknowledgment
{
    private const int DuplicateThreshold = 3;
    private const int ReorderWindowDivisor = 4; // reo_wnd starts at min_RTT / 4.
    private const int ReorderWindowPersistence = 16; // Recoveries before a widened window decays (RFC 8985 6.2 step 4).

    private DateTimeOffset? _deliveredSendTime; // RACK.xmit_ts
    private long _deliveredOrder; // Send order of that segment, standing in for RACK.end_seq as the tie-breaker.
    private TimeSpan _rtt; // RACK.rtt
    private SequenceNumber? _highestSacked; // RACK.fack
    private bool _reorderingSeen;
    private int _reorderMultiplier = 1; // RACK.reo_wnd_mult
    private int _reorderPersist;
    private SequenceNumber? _duplicateRound; // RACK.dsack_round

    /// <summary>
    /// Step 2 and 3: a segment was newly acknowledged or SACKed. Unless the delivery is ambiguous (a retransmitted
    /// segment whose ACK may be for the original), it becomes the reference if it was sent more recently, and a
    /// never-retransmitted segment delivered below the highest SACK reveals reordering.
    /// </summary>
    /// <param name="segment">The delivered segment.</param>
    /// <param name="now">Current time.</param>
    /// <param name="minimumRtt">Smallest RTT measured so far.</param>
    /// <param name="echoedTimestamp">TSecr of the ACK when timestamps are in use, which disambiguates retransmissions.</param>
    public void OnDelivered(UnackedSegment segment, DateTimeOffset now, TimeSpan? minimumRtt, uint? echoedTimestamp)
    {
        if (!segment.Retransmitted && _highestSacked is { } fack && segment.End < fack) _reorderingSeen = true;
        if (segment.Sacked && (_highestSacked is not { } highest || highest < segment.End)) _highestSacked = segment.End;
        if (segment.Retransmitted && IsAmbiguous(segment, now, minimumRtt, echoedTimestamp)) return;
        _rtt = now - segment.LastSent;
        if (_deliveredSendTime is { } time && !IsNewer(segment.LastSent, segment.TransmitOrder, time, _deliveredOrder)) return;
        _deliveredSendTime = segment.LastSent;
        _deliveredOrder = segment.TransmitOrder;
    }

    /// <summary>
    /// Step 4: adapts the reordering window. A D-SACK means a retransmission was spurious, so the window widens by
    /// another min_RTT / 4 for the next 16 recoveries (at most once per round trip).
    /// </summary>
    public void OnAcknowledgment(bool duplicateReported, bool recoveryEnded, SequenceNumber sendUnacknowledged, SequenceNumber sendNext)
    {
        if (_duplicateRound is { } round && round <= sendUnacknowledged) _duplicateRound = null;
        if (duplicateReported && _duplicateRound is null)
        {
            _duplicateRound = sendNext;
            _reorderMultiplier++;
            _reorderPersist = ReorderWindowPersistence;
        }
        else if (recoveryEnded && _reorderPersist > 0 && --_reorderPersist == 0)
        {
            _reorderMultiplier = 1;
        }
    }

    /// <summary>
    /// RACK.reo_wnd (RFC 8985 6.2 step 4): zero while no reordering has been observed and either recovery is under
    /// way or enough is SACKed to meet the classic three-duplicate rule; otherwise a multiple of min_RTT / 4,
    /// capped at SRTT.
    /// </summary>
    public TimeSpan ReorderWindow(TimeSpan? minimumRtt, TimeSpan? smoothedRtt, bool inRecovery, int sackedSegments)
    {
        if (!_reorderingSeen && (inRecovery || sackedSegments >= DuplicateThreshold)) return TimeSpan.Zero;
        var window = (minimumRtt ?? TimeSpan.Zero) / ReorderWindowDivisor * _reorderMultiplier;
        return smoothedRtt is { } srtt && srtt < window ? srtt : window;
    }

    /// <summary>
    /// Step 5: marks as lost every segment still outstanding that was sent before the reference delivery and has
    /// waited longer than RACK.rtt + reorder window.
    /// </summary>
    /// <returns>When the next not-yet-overdue candidate becomes overdue, for the reorder timer; null when none waits.</returns>
    public DateTimeOffset? DetectLosses(RetransmissionQueue queue, DateTimeOffset now, TimeSpan reorderWindow)
    {
        if (_deliveredSendTime is not { } reference) return null;
        DateTimeOffset? timer = null;
        foreach (var segment in queue.Segments)
        {
            if (segment.Sacked || segment.Lost || !IsNewer(reference, _deliveredOrder, segment.LastSent, segment.TransmitOrder)) continue;
            var deadline = segment.LastSent + _rtt + reorderWindow;
            if (deadline <= now) segment.Lost = true;
            else if (timer is not { } earliest || deadline < earliest) timer = deadline;
        }
        return timer;
    }

    /// <summary>
    /// A retransmitted segment's delivery may be of the original: timestamps say so directly, and without them a
    /// delivery sooner than min_RTT after the resend cannot be the resend's.
    /// </summary>
    private static bool IsAmbiguous(UnackedSegment segment, DateTimeOffset now, TimeSpan? minimumRtt, uint? echoedTimestamp)
    {
        if (echoedTimestamp is { } echo) return unchecked((int)(echo - segment.TimestampValue)) < 0;
        return minimumRtt is { } minimum && now - segment.LastSent < minimum;
    }

    /// <summary>
    /// RFC 8985 6.2: sent later, or at the same time but afterwards. The RFC breaks ties by end sequence, which
    /// orders original transmissions; send order also orders a retransmission after the data it follows.
    /// </summary>
    private static bool IsNewer(DateTimeOffset time1, long order1, DateTimeOffset time2, long order2) =>
        time1 > time2 || (time1 == time2 && order1 > order2);
}
