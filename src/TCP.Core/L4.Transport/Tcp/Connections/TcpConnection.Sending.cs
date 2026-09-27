using TCP.L3.Network.IPv4;
using TCP.L3.Network.Icmp;
using TCP.L4.Transport.Tcp.Reliability;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>Transmission, retransmission and path MTU reaction.</summary>
/// <remarks>
/// <para>
/// The outbound half of the connection. <see cref="Flush"/> decides when queued bytes become segments, resending
/// presumed-lost segments before new data (RFC 6675 NextSeg). <see cref="Transmit"/> assigns sequence numbers and
/// keeps copies for retransmission. <see cref="SendSegment"/> stamps each segment with our acknowledgment, window,
/// options and signature and hands it to <see cref="TcpHost"/>.
/// </para>
/// <para>
/// How much may be in flight is min(peer window, cwnd), where the congestion side counts "pipe" (data still in the
/// network, excluding what SACK or duplicate ACKs show has left it) rather than all unacknowledged bytes. That one
/// rule gives limited transmit (RFC 3042) and SACK-based recovery (RFC 6675) without special cases.
/// </para>
/// </remarks>
public sealed partial class TcpConnection
{
    private const uint NextHopMtuMask = ushort.MaxValue;
    private const byte EcnCapableTransport = 0b10; // ECT(0) in the IPv4 ECN field (RFC 3168 5).
    /// <summary>
    /// RFC 1191 plateau table for legacy ICMP reports that omit the next-hop MTU: common link MTUs, largest first.
    /// </summary>
    private static ReadOnlySpan<int> LegacyPathMtuPlateaus =>
        [IPv4Packet.MaximumTotalLength, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, IPv4Constants.MinimumMtu];

    /// <summary>
    /// Sends what the windows allow: presumed-lost segments first, then queued data, then a requested FIN; finally
    /// re-arms the tail loss probe.
    /// </summary>
    /// <remarks>
    /// Called whenever sending might become possible: after <see cref="Send"/>, <see cref="Close"/>, each incoming
    /// segment and each tick. A re-entrancy guard stops a synchronous ACK delivered mid-send from nesting a second flush.
    /// </remarks>
    private void Flush()
    {
        if (_flushing || IsClosed) return;
        _flushing = true;
        try
        {
            if (!IsSynchronizing || FastOpenAccepted) ResendLost();
            if (!SendSideOpen) return;
            RestartAfterIdle();
            SendQueuedData();
            if (ReadyToSendFin) SendFin();
        }
        finally
        {
            _flushing = false;
            UpdateTailLossProbe();
        }
    }

    /// <summary>Cuts the unsent queue into segments and transmits them until the queue empties or a rule says wait.</summary>
    private void SendQueuedData()
    {
        while (_unsent.Count > 0 && SendSideOpen)
        {
            var size = NextSegmentSize();
            if (size == 0) return;
            Transmit(TcpFlags.Ack | TcpFlags.Psh, _unsent.Dequeue(size));
        }
    }

    /// <summary>
    /// RFC 5681 4.1: after an idle period longer than the RTO the ACK clock is gone, so a full cwnd would go out as
    /// one burst. Shrink it to the initial window first.
    /// </summary>
    private void RestartAfterIdle()
    {
        if (_unsent.Count == 0 || !_unacknowledged.IsEmpty || Now - _lastSent <= _rtt.Timeout) return;
        _congestion.OnIdleRestart(MaximumSegmentSize, _settings.InitialWindowSegments);
    }

    /// <summary>Room under the congestion window: cwnd minus pipe.</summary>
    private long CongestionRoom => (long)_congestion.Window - Pipe;

    /// <summary>
    /// Sequence space presumed still in the network. With SACK, SACKed and lost segments are excluded (RFC 6675).
    /// Without it each duplicate ACK stands for one segment that left the network, as Reno's window inflation assumes.
    /// </summary>
    private long Pipe => _sackPermitted
        ? _unacknowledged.Pipe
        : Math.Max(0, _unacknowledged.Pipe - (long)_duplicateAcks * MaximumSegmentSize);

    /// <summary>
    /// Sizes the next data segment: no more than the peer's window, the congestion room, the MSS or what is queued.
    /// Returns zero when a window is full or when Nagle or sender SWS avoidance says to hold off.
    /// </summary>
    /// <returns>How many queued bytes to send now, or zero to wait for an ACK.</returns>
    private int NextSegmentSize()
    {
        var usable = Math.Min((long)_sendWindow.Size - FlightSize, CongestionRoom);
        if (usable <= 0 || NagleDefers) return 0;
        var size = (int)Math.Min(Math.Min(usable, MaximumSegmentSize), _unsent.Count);
        return SenderSwsAvoidanceDefers(size) ? 0 : size;
    }

    /// <summary>Nagle (RFC 896): hold back a sub-MSS remainder while earlier data is unacknowledged. Urgent data is exempt.</summary>
    private bool NagleDefers =>
        !NoDelay && !_closeRequested && _sendUrgentEnd is null && _unacknowledged.HasData && _unsent.Count < MaximumSegmentSize;

    /// <summary>
    /// Sender SWS avoidance (RFC 1122 4.2.3.4): while data is in flight, wait for its ACK rather than filling a
    /// small window opening with a sub-MSS segment. With nothing in flight, send so the stream cannot stall.
    /// </summary>
    private bool SenderSwsAvoidanceDefers(int size) =>
        size < MaximumSegmentSize && size < _unsent.Count && size < _sendWindow.Largest / 2 && !_unacknowledged.IsEmpty;

    /// <summary>The application asked to close, every byte has gone out, and the window has room for the FIN's sequence number.</summary>
    private bool ReadyToSendFin =>
        _closeRequested && _unsent.Count == 0 && SendSideOpen && FlightSize < _sendWindow.Size && CongestionRoom > 0;

    /// <summary>
    /// Closes our direction: ESTABLISHED → FIN-WAIT-1 (we close first) or CLOSE-WAIT → LAST-ACK (the peer
    /// already closed). The FIN is queued for retransmission like data.
    /// </summary>
    private void SendFin()
    {
        EnterState(State == TcpState.CloseWait ? TcpState.LastAck : TcpState.FinWait1);
        Transmit(TcpFlags.Fin | TcpFlags.Ack, []);
    }

    /// <summary>Sends new sequence space and keeps it for retransmission until acknowledged.</summary>
    /// <remarks>
    /// This is the only place SND.NXT advances. Use it for anything that consumes sequence numbers (data, SYN,
    /// FIN); pure ACKs go through <see cref="SendSegment"/> directly. Starts the retransmission timer if nothing
    /// else was in flight.
    /// </remarks>
    private void Transmit(TcpFlags flags, byte[] data)
    {
        // Application callbacks may have aborted during the preceding state change.
        if (IsClosed) return;
        var segment = new UnackedSegment(_sendNext, flags, data, Now) { TimestampValue = TimestampClock, TransmitOrder = ++_transmitCount };
        var wasIdle = _unacknowledged.IsEmpty;
        _unacknowledged.Add(segment);
        _sendNext = segment.End;
        _sendNext64 += segment.Length;
        if (wasIdle)
        {
            _retransmitAt = _rtt.DeadlineFrom(Now);
            _lastProgress = Now;
        }
        if (_advertiseUserTimeout) _userTimeoutCarriedThrough = segment.End;
        if (data.Length > 0) _restartTailLossProbe = true;
        SendSegment(segment.Sequence, flags, data);
    }

    /// <summary>
    /// Sends a bare ACK stating RCV.NXT and our current window. It consumes no sequence space, so it is never
    /// retransmitted.
    /// </summary>
    private void SendAck() => SendSegment(_sendNext, TcpFlags.Ack, []);

    /// <summary>Puts one segment on the wire, advertising the current receive window.</summary>
    /// <remarks>
    /// Every outgoing segment passes through here, so every segment carries a fresh acknowledgment, window,
    /// timestamp and SACK information, and cancels any delayed ACK. It also applies ECN: ECE while echoing congestion,
    /// CWR once after reducing, and the ECT codepoint on new data (never on retransmissions, pure ACKs or SYNs,
    /// RFC 3168 6.1.4-6). Does nothing once closed.
    /// </remarks>
    private void SendSegment(SequenceNumber sequence, TcpFlags flags, byte[] data, bool retransmission = false)
    {
        if (IsClosed) return;
        var ack = (flags & TcpFlags.Ack) != TcpFlags.None;
        var syn = (flags & TcpFlags.Syn) != TcpFlags.None;
        if (_ecn && ack && !syn && _ecnEcho) flags |= TcpFlags.Ece;
        if (_ecn && _sendCongestionWindowReduced && data.Length > 0 && !retransmission)
        {
            flags |= TcpFlags.Cwr;
            _sendCongestionWindowReduced = false;
        }
        var urgentPointer = UrgentPointerFor(sequence, ref flags);
        var (options, macOffset) = BuildOptions(flags, data.Length);
        var acknowledgment = ack ? _receive.Next.Value : TcpWireFormat.UnusedAcknowledgmentNumber;
        var window = AdvertisedWindow(syn);
        var segment = new TcpSegment(LocalPort, RemotePort, sequence.Value, acknowledgment, flags, window, data, options, urgentPointer);
        if (_authenticator is not null && macOffset is { } offset)
            segment = _authenticator.Sign(segment, offset, syn && !ack ? 0 : SequenceExtension(sequence, _sendNext64));
        if (ack) NoteAcknowledgmentSent();
        if (data.Length > 0 || syn || (flags & TcpFlags.Fin) != TcpFlags.None) _lastSent = Now;
        var ecnCapable = _ecn && data.Length > 0 && !syn && !retransmission;
        _host.Send(this, segment, ecnCapable ? EcnCapableTransport : (byte)0);
    }

    /// <summary>
    /// The window field: a SYN's is never scaled (RFC 7323 2.2); later ones are shifted right by our scale, rounding
    /// up so the advertised right edge never moves backward. Records what the peer will understand.
    /// </summary>
    private ushort AdvertisedWindow(bool syn)
    {
        var window = ReceiveWindow;
        var shift = syn ? 0 : _receiveScale;
        var field = Math.Min(TcpWireFormat.MaximumUnscaledWindow, (int)(((long)window + (1 << shift) - 1) >> shift));
        _receive.RecordAdvertisement(field << shift);
        return (ushort)field;
    }

    /// <summary>
    /// Sets URG and the urgent pointer on segments that precede the end of urgent data (RFC 9293 3.8.5, RFC 6093:
    /// the pointer is the offset of the byte after the last urgent byte). The pointer saturates for distant ends.
    /// </summary>
    private ushort UrgentPointerFor(SequenceNumber sequence, ref TcpFlags flags)
    {
        if (_sendUrgentEnd is not { } end || !(sequence < end)) return TcpWireFormat.NoUrgentPointer;
        flags |= TcpFlags.Urg;
        return (ushort)Math.Min(end - sequence, ushort.MaxValue);
    }

    /// <summary>Resends the oldest unacknowledged segment and restarts the retransmission timer.</summary>
    private void Retransmit()
    {
        if (_unacknowledged.IsEmpty) return;
        // Fast retransmit must also postpone the old timeout. Set this before sending,
        // which can synchronously deliver an ACK and update the timer again.
        _retransmitAt = _rtt.DeadlineFrom(Now);
        if (!IsSynchronizing) _unacknowledged.SplitOversized(MaximumSegmentSize);
        Resend(_unacknowledged.Oldest);
    }

    /// <summary>Resends one queued segment. Callers first split the queue to the current MSS, so it fits whole.</summary>
    private void Resend(UnackedSegment segment)
    {
        segment.Retransmitted = true;
        segment.Lost = false;
        segment.LastSent = Now;
        segment.TimestampValue = TimestampClock;
        segment.TransmitOrder = ++_transmitCount;
        Retransmissions++;
        SendSegment(segment.Sequence, segment.Flags, segment.Data, retransmission: true);
    }

    /// <summary>
    /// Resends presumed-lost segments in sequence order while the congestion window has room (RFC 6675 NextSeg rule 1,
    /// RFC 5681 3.1 after a timeout). When nothing is in the pipe one segment always goes, so recovery cannot stall.
    /// </summary>
    private void ResendLost()
    {
        if (!_unacknowledged.HasLost) return;
        _unacknowledged.SplitOversized(MaximumSegmentSize);
        // Resend can deliver synchronously and change the queue, so iterate over a snapshot.
        foreach (var segment in _unacknowledged.Snapshot())
        {
            if (!segment.Lost) continue;
            if (Pipe > 0 && CongestionRoom < segment.Length) break;
            if (IsClosed || !_unacknowledged.Contains(segment)) break;
            Resend(segment);
        }
    }

    /// <summary>
    /// The tail loss probe (RFC 8985 7.3): one new segment if the peer's window allows, otherwise the last segment
    /// again. Its ACK lets RACK find and repair a lost tail without waiting for the retransmission timeout.
    /// </summary>
    private void SendTailLossProbe()
    {
        if (_unacknowledged.IsEmpty || InRecovery || IsClosed)
        {
            _tailLossProbe.Disarm();
            return;
        }
        var newData = _unsent.Count > 0 && (long)_sendWindow.Size - FlightSize > 0 && SendSideOpen;
        if (newData)
        {
            var size = (int)Math.Min(Math.Min((long)_sendWindow.Size - FlightSize, MaximumSegmentSize), _unsent.Count);
            Transmit(TcpFlags.Ack | TcpFlags.Psh, _unsent.Dequeue(size));
        }
        else
        {
            _unacknowledged.SplitOversized(MaximumSegmentSize);
            Resend(_unacknowledged.Newest);
        }
        _tailLossProbe.ProbeSent(_sendNext, retransmission: !newData);
        _retransmitAt = _rtt.DeadlineFrom(Now);
    }

    /// <summary>
    /// Keeps the probe timer in step (RFC 8985 7.2). It applies only in the open state: SACK in use, data outstanding,
    /// no fast or timeout recovery, the peer's window open and no probe outstanding. It restarts when new data goes
    /// out or an ACK arrives, and otherwise keeps its deadline so that it can expire.
    /// </summary>
    private void UpdateTailLossProbe()
    {
        var restart = _restartTailLossProbe;
        _restartTailLossProbe = false;
        var eligible = _settings.RecentAcknowledgment && _sackPermitted && !IsSynchronizing && !InRecovery && !IsClosed &&
                       _timeoutRecoveryPoint is null && !_unacknowledged.IsEmpty && !_tailLossProbe.ProbeOutstanding &&
                       _sendWindow.Size > 0;
        if (!eligible) _tailLossProbe.Disarm();
        else if (restart || _tailLossProbe.Deadline is null)
            _tailLossProbe.Arm(Now, _rtt.SmoothedRtt, _unacknowledged.Count == 1, TailLossProbe.WorstCaseDelayedAck, _retransmitAt);
    }

    /// <summary>Reacts to a validated ICMP error that quotes <paramref name="sequence"/> from this connection.</summary>
    internal void NetworkError(uint sequence, IcmpPacket message, int quotedLength)
    {
        // Only a report about data still awaiting acknowledgment can be ours and current.
        if (!_unacknowledged.Covers(sequence)) return;
        LastNetworkError = string.Format(TcpMessages.NetworkErrorFormat, message.Type, message.Code);
        if (IsFragmentationNeeded(message)) ReducePathMtu(message, quotedLength);
        else if (IsPeerUnreachable(message) && IsSynchronizing) Fail(string.Format(TcpMessages.ConnectionFailedFormat, LastNetworkError));
    }

    /// <summary>ICMP type 3 code 4: a router dropped our Don't-Fragment packet as too big for the next link.</summary>
    private static bool IsFragmentationNeeded(IcmpPacket message) =>
        message.Type == (byte)IcmpMessageType.DestinationUnreachable &&
        message.Code == (byte)IcmpDestinationUnreachableCode.FragmentationNeeded;

    /// <summary>
    /// ICMP type 3 codes 2 and 3: the peer host has no TCP, or nothing on that port. Treated as a hard error only
    /// during the handshake (RFC 5461), since later it more likely signals a transient or forged report.
    /// </summary>
    private static bool IsPeerUnreachable(IcmpPacket message) =>
        message.Type == (byte)IcmpMessageType.DestinationUnreachable &&
        message.Code is (byte)IcmpDestinationUnreachableCode.ProtocolUnreachable or (byte)IcmpDestinationUnreachableCode.PortUnreachable;

    /// <summary>
    /// Path MTU discovery (RFC 1191): shrink segments to the reported MTU. Every segment in flight that no longer
    /// fits was dropped too, so it is cut to the new size and resent as the window allows.
    /// </summary>
    private void ReducePathMtu(IcmpPacket message, int quotedLength)
    {
        var mtu = (int)(message.RestOfHeader & NextHopMtuMask);
        if (mtu == 0) mtu = FindLegacyPathMtu(quotedLength);
        if (mtu < IPv4Constants.MinimumMtu || mtu >= quotedLength || mtu >= _pathMtu) return;
        LowerPathMtu(mtu);
        Retransmit();
        if (!IsClosed) ResendLost();
    }

    /// <summary>Adopts a smaller path MTU and presumes lost every segment in flight that exceeds it.</summary>
    private void LowerPathMtu(int mtu)
    {
        _pathMtu = mtu;
        _pathMtuLoweredAt = Now;
        _unacknowledged.MarkOversizedLost(MaximumSegmentSize);
    }

    /// <summary>
    /// Old routers send "fragmentation needed" without the next-hop MTU. Guess the next plateau below the size
    /// of the packet that failed (RFC 1191 section 7).
    /// </summary>
    /// <returns>The guessed MTU, or 0 when no plateau is smaller.</returns>
    private static int FindLegacyPathMtu(int quotedLength)
    {
        foreach (var plateau in LegacyPathMtuPlateaus)
            if (plateau < quotedLength) return plateau;
        return 0; // No supported plateau below the quoted packet size.
    }
}
