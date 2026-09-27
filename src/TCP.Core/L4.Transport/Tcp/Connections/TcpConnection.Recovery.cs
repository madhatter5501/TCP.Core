using TCP.L4.Transport.Tcp.Reliability;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>Acknowledgment processing, loss detection and loss recovery.</summary>
/// <remarks>
/// <para>Each acceptable ACK goes through <see cref="ProcessAcknowledgment"/>, in this order:</para>
/// <list type="number">
/// <item>Apply the cumulative ACK and the SACK blocks to the scoreboard.</item>
/// <item>Measure the RTT: from the echoed timestamp when timestamps are in use, otherwise from a segment sent once (Karn).</item>
/// <item>Check whether a retransmission timeout was spurious (Eifel detection, RFC 3522) and undo it.</item>
/// <item>Detect losses: RACK's time rule when SACK is in use (RFC 8985), otherwise three duplicate ACKs and NewReno partial ACKs (RFC 6582).</item>
/// <item>Enter or leave fast recovery, reducing the congestion window once per loss episode.</item>
/// <item>React to ECN echoes and to tail loss probes that repaired a loss.</item>
/// <item>Grow the congestion window if not recovering.</item>
/// </list>
/// <para>What to resend is then decided by <see cref="Flush"/>, which sends lost segments first.</para>
/// </remarks>
public sealed partial class TcpConnection
{
    private const int DuplicateAckThreshold = 3;
    private static readonly TimeSpan Millisecond = TimeSpan.FromMilliseconds(1);

    private bool _inRecovery;
    private SequenceNumber? _timeoutRecoveryPoint; // SND.NXT at a retransmission timeout; recovering until acknowledged.
    private long _transmitCount;
    private bool _restartTailLossProbe;
    private SequenceNumber _recoveryPoint; // SND.NXT when recovery began.
    private int _duplicateAcks;
    private DateTimeOffset? _reorderTimer;
    private uint? _timeoutRetransmitTimestamp; // TSval of the retransmission a timeout sent, for Eifel detection.
    private bool _ecnEcho; // Receiver: echo ECE until the sender answers with CWR.
    private bool _sendCongestionWindowReduced; // Sender: set CWR on the next new data segment.
    private SequenceNumber? _ecnReductionPoint; // Congestion was already answered for data below this.

    /// <summary>Fast recovery is under way.</summary>
    private bool InRecovery => _inRecovery;

    /// <summary>
    /// Applies an acceptable ACK to send state. Stale ACKs (below SND.UNA) are ignored. Otherwise it updates the
    /// peer's window and persist timer, the scoreboard, RTT, loss detection and congestion control.
    /// </summary>
    private void ProcessAcknowledgment(TcpSegment segment, TcpOptions options)
    {
        SequenceNumber acknowledgment = segment.AcknowledgmentNumber;
        if (acknowledgment < _sendUnacknowledged) return;
        // A valid ACK is evidence the peer is alive, even when its window stays shut.
        _persist.PeerResponded();
        var previousWindow = _sendWindow.Size;
        _sendWindow.Update(segment);
        ReschedulePersistTimer(previousWindow);
        var advanced = _sendUnacknowledged < acknowledgment;
        var bytesAcknowledged = acknowledgment - _sendUnacknowledged;
        var acknowledged = advanced ? _unacknowledged.RemoveAcknowledged(acknowledgment) : null;
        var sack = _sackPermitted && options.SackBlocks.Count > 0
            ? _unacknowledged.ApplySack(options.SackBlocks, acknowledgment, _sendNext)
            : new SackOutcome([], null);
        var echo = _timestamps ? options.Timestamp?.EchoReply : null;
        var duplicate = !advanced && IsDuplicateAck(segment, previousWindow);
        if (advanced) AdvanceSendUnacknowledged(acknowledgment, acknowledged!, echo);
        else if (duplicate) _duplicateAcks++;
        foreach (var delivered in (acknowledged?.Completed ?? []).Concat(sack.NewlySacked))
            _rack.OnDelivered(delivered, Now, _rtt.MinimumRtt, echo);
        if (_tailLossProbe.OnAcknowledgment(acknowledgment, CoversProbe(sack.DuplicateBlock), duplicate && sack.NewlySacked.Count == 0))
            RespondToCongestion();
        if (_ecn && segment.Has(TcpFlags.Ece) && !segment.Has(TcpFlags.Syn)) RespondToCongestion();
        if (_timeoutRecoveryPoint is { } timeoutPoint && timeoutPoint <= _sendUnacknowledged) _timeoutRecoveryPoint = null;
        if (advanced || sack.NewlySacked.Count > 0) _restartTailLossProbe = true;
        var recoveryEnded = _inRecovery && _recoveryPoint <= _sendUnacknowledged;
        if (recoveryEnded)
        {
            _inRecovery = false;
            _duplicateAcks = 0;
        }
        _rack.OnAcknowledgment(sack.DuplicateBlock is not null, recoveryEnded, _sendUnacknowledged, _sendNext);
        DetectLosses(advanced);
        if (advanced && !_inRecovery) _congestion.OnAcknowledged(bytesAcknowledged, MaximumSegmentSize, Now, _rtt.SmoothedRtt);
        if (advanced) AfterNewAcknowledgment(acknowledged!);
    }

    /// <summary>Keeps the zero-window probe schedule in step with the window just learned: reset when open, first probe one RTO after it closes.</summary>
    private void ReschedulePersistTimer(uint previousWindow)
    {
        if (_sendWindow.Size > 0) _persist.WindowOpened(Now, _rtt.TimeoutSeconds);
        else if (previousWindow > 0) _persist.WindowClosed(Now, _rtt.TimeoutSeconds);
    }

    /// <summary>RFC 5681 2: a bare ACK that repeats SND.UNA, with data outstanding and the window unchanged.</summary>
    private bool IsDuplicateAck(TcpSegment segment, uint previousWindow) =>
        !_unacknowledged.IsEmpty && segment.Payload.IsEmpty && !segment.Has(TcpFlags.Syn | TcpFlags.Fin) &&
        _sendWindow.Size == previousWindow && _sendWindow.Size > 0;

    /// <summary>
    /// SND.UNA moves forward: take an RTT sample, check for a spurious timeout, restart the retransmission timer and
    /// the user timeout clock, and let NewReno's emulated SACK count shrink with the acknowledged segments.
    /// </summary>
    private void AdvanceSendUnacknowledged(SequenceNumber acknowledgment, AcknowledgedSegments acknowledged, uint? echo)
    {
        UpdateRoundTripTime(acknowledged, echo);
        DetectSpuriousTimeout(echo);
        _sendUnacknowledged = acknowledgment;
        _consecutiveTimeouts = 0;
        _retransmitAt = _rtt.DeadlineFrom(Now);
        _lastProgress = Now;
        _duplicateAcks = _inRecovery ? Math.Max(0, _duplicateAcks - acknowledged.Completed.Count) : 0;
        if (_sendUrgentEnd is { } urgentEnd && urgentEnd <= acknowledgment) _sendUrgentEnd = null;
        if (_userTimeoutCarriedThrough is { } carried && carried <= acknowledgment) _advertiseUserTimeout = false;
    }

    /// <summary>
    /// Feeds the RTT estimator. With timestamps every ACK of new data is a sample, even of a retransmission, because
    /// TSecr says which transmission it answers (RFC 7323 4). Without them, time the oldest newly acknowledged
    /// segment if Karn's algorithm allows.
    /// </summary>
    private void UpdateRoundTripTime(AcknowledgedSegments acknowledged, uint? echo)
    {
        if (acknowledged.IncludesRetransmittedSyn) _rtt.ApplySynRetransmissionFloor();
        if (echo is { } echoed && unchecked((int)(TimestampClock - echoed)) is >= 0 and var elapsed)
            _rtt.AddSample(Millisecond * elapsed);
        else if (acknowledged.RoundTripSample is { } timed) _rtt.AddSample(Now - timed.FirstSent);
    }

    /// <summary>
    /// Eifel detection (RFC 3522): if the first ACK after a timeout echoes a timestamp older than the retransmission,
    /// it answers the original transmission, so the timeout was spurious. Restore the congestion window and RTO and
    /// withdraw the loss presumptions instead of resending everything (RFC 4015).
    /// </summary>
    private void DetectSpuriousTimeout(uint? echo)
    {
        if (_timeoutRetransmitTimestamp is not { } retransmitted) return;
        _timeoutRetransmitTimestamp = null;
        if (echo is not { } echoed || unchecked((int)(echoed - retransmitted)) >= 0) return;
        if (!_congestion.UndoReduction()) return;
        SpuriousRetransmissionTimeouts++;
        _rtt.ResetBackoff();
        _unacknowledged.ClearLost();
    }

    /// <summary>
    /// Marks presumed-lost segments, and enters fast recovery if any are found. With SACK and RACK, the time rule
    /// decides; with SACK alone, three SACKed segments above a hole (RFC 6675 IsLost); without SACK, the third
    /// duplicate ACK marks the oldest segment, and during recovery each partial ACK marks the next (RFC 6582).
    /// </summary>
    private void DetectLosses(bool advanced)
    {
        if (_unacknowledged.IsEmpty || IsSynchronizing) return;
        if (_sackPermitted && _settings.RecentAcknowledgment) DetectLossesByTime();
        else if (_sackPermitted) DetectLossesByDuplicateThreshold();
        else if (!_inRecovery && _duplicateAcks >= DuplicateAckThreshold) _unacknowledged.Oldest.Lost = true;
        else if (_inRecovery && advanced && !_unacknowledged.Oldest.Retransmitted) _unacknowledged.Oldest.Lost = true;
        // After a timeout, lost segments are resent in slow start rather than by entering fast recovery.
        if (!_inRecovery && _timeoutRecoveryPoint is null && _unacknowledged.HasLost) EnterRecovery();
    }

    /// <summary>RACK: mark overdue segments and set the reorder timer for the rest (RFC 8985 6.2 step 5).</summary>
    private void DetectLossesByTime()
    {
        var window = _rack.ReorderWindow(_rtt.MinimumRtt, _rtt.SmoothedRtt, _inRecovery, _unacknowledged.SackedCount);
        _reorderTimer = _rack.DetectLosses(_unacknowledged, Now, window);
    }

    /// <summary>RFC 6675 IsLost: a segment with at least three SACKed segments above it is lost.</summary>
    private void DetectLossesByDuplicateThreshold()
    {
        var sackedAbove = 0;
        for (var i = _unacknowledged.Count - 1; i >= 0; i--)
        {
            var segment = _unacknowledged.Segments[i];
            if (segment.Sacked) sackedAbove++;
            else if (sackedAbove >= DuplicateAckThreshold && !segment.Retransmitted) segment.Lost = true;
        }
    }

    /// <summary>
    /// Fast retransmit and recovery (RFC 5681 3.2, RFC 6675 5): reduce the congestion window once for this episode,
    /// remember SND.NXT as the recovery point, and resend the first lost segment at once regardless of the window.
    /// </summary>
    private void EnterRecovery()
    {
        _inRecovery = true;
        _recoveryPoint = _sendNext;
        _tailLossProbe.Reset();
        RespondToCongestion();
        var first = _unacknowledged.Segments.FirstOrDefault(s => s.Lost);
        if (first is null) return;
        _retransmitAt = _rtt.DeadlineFrom(Now);
        _unacknowledged.SplitOversized(MaximumSegmentSize);
        Resend(first);
    }

    /// <summary>
    /// One congestion response per window of data (RFC 3168 6.1.2, RFC 5681 3.2): losses, ECN echoes and repaired
    /// tail losses within the same window share it. After an ECN-triggered reduction, CWR tells the receiver to stop
    /// echoing.
    /// </summary>
    private void RespondToCongestion()
    {
        if (_ecnReductionPoint is { } point && _sendUnacknowledged < point) return;
        _congestion.OnCongestionEvent(FlightSize, MaximumSegmentSize, Now);
        _ecnReductionPoint = _sendNext;
        if (_ecn) _sendCongestionWindowReduced = true;
    }

    /// <summary>Whether a D-SACK block covers the last segment, which a retransmitted tail loss probe resent.</summary>
    private bool CoversProbe(SackBlock? duplicate) =>
        duplicate is { } block && _sendNext <= block.End + TcpWireFormat.ControlSequenceLength && block.End <= _sendNext;

    /// <summary>
    /// After SND.UNA advances: advance the close handshake if our FIN was covered, stop the timer when nothing is
    /// outstanding, and tell the application there is room to send.
    /// </summary>
    private void AfterNewAcknowledgment(AcknowledgedSegments acknowledged)
    {
        if (_unacknowledged.IsEmpty) _reorderTimer = null;
        if (acknowledged.IncludesFin) OurFinAcknowledged();
        if (!_closeRequested && SendSideOpen) SendReady?.Invoke(this);
    }

    /// <summary>The reorder timer expired (RFC 8985 6.3): segments RACK was waiting on are now overdue.</summary>
    private void ReorderTimeout()
    {
        _reorderTimer = null;
        DetectLosses(advanced: false);
    }
}
