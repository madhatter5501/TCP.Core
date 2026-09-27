using TCP.L4.Transport.Tcp.Reliability;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>Segment arrival, in the order of RFC 9293 3.10.7, and the acknowledgment policy for received data.</summary>
public sealed partial class TcpConnection
{
    private bool _ackPending;
    private DateTimeOffset _ackDeadline;
    private int _bytesSinceAck;
    private int _largestReceivedSegment;

    /// <summary>
    /// Processes one segment that <see cref="TcpHost"/> routed here. It is the "SEGMENT ARRIVES" event of
    /// RFC 9293 3.10.7.4, checked in the RFC's order:
    /// </summary>
    /// <remarks>
    /// <list type="number">
    /// <item>Authentication (TCP-AO or MD5), when a key covers the peer.</item>
    /// <item>Handshake special cases.</item>
    /// <item>PAWS (RFC 7323 5) and sequence acceptability.</item>
    /// <item>RST.</item>
    /// <item>SYN.</item>
    /// <item>ACK.</item>
    /// <item>URG.</item>
    /// <item>Data and FIN.</item>
    /// </list>
    /// <para>Any step can close the connection, so later steps re-check <see cref="IsClosed"/>.</para>
    /// </remarks>
    /// <param name="segment">The arriving segment.</param>
    /// <param name="congestionExperienced">The IP header carried the ECN Congestion Experienced mark.</param>
    internal void Receive(TcpSegment segment, bool congestionExperienced = false)
    {
        if (IsClosed || !TryReadOptions(segment, out var options) || !IsAuthentic(segment, options)) return;
        _lastReceived = Now;
        _keepAliveProbes = 0;
        if (State == TcpState.SynSent)
        {
            ReceiveInSynSent(segment, options, congestionExperienced);
            return;
        }
        if (State == TcpState.TimeWait && segment.Has(TcpFlags.Rst)) return;
        if (IsPeerSynAgain(segment))
        {
            ReceivePeerSynAgain(segment, options, congestionExperienced);
            return;
        }
        if (IsRetransmittedFinInTimeWait(segment))
        {
            RestartTimeWait();
            return;
        }
        if (FailsPaws(segment, options) || (!IsAcceptable(segment) && !IsAtClosedWindowEdge(segment)))
        {
            if (segment.Has(TcpFlags.Rst)) return;
            if (IsOldDuplicate(segment)) _receive.ReportDuplicate(segment.SequenceNumber, (uint)segment.Payload.Length);
            SendAck();
            return;
        }
        if (segment.Has(TcpFlags.Rst))
        {
            ReceiveReset(segment);
            return;
        }
        if (segment.Has(TcpFlags.Syn))
        {
            SendChallengeAck();
            return;
        }
        if (!segment.Has(TcpFlags.Ack)) return;
        UpdateRecentTimestamp(segment, options);
        if (options.UserTimeout is { } timeout) AdoptPeerUserTimeout(timeout);
        if (State == TcpState.TimeWait)
        {
            if (segment.SequenceLength > 0) SendAck();
            return;
        }
        if (!ReceiveAcknowledgment(segment, options) || IsClosed) return;
        ReceiveUrgentPointer(segment);
        if (IsClosed) return;
        if (_ecn && segment.Has(TcpFlags.Cwr)) _ecnEcho = false;
        ReceiveStreamContent(segment, congestionExperienced);
        Flush();
    }

    /// <summary>Decodes the options; a segment built with malformed ones (only possible in-process) is dropped.</summary>
    private static bool TryReadOptions(TcpSegment segment, out TcpOptions options)
    {
        try
        {
            options = segment.ReadOptions();
            return true;
        }
        catch (ArgumentException)
        {
            options = TcpOptions.None;
            return false;
        }
    }

    /// <summary>
    /// RFC 5925 7.7 and RFC 2385: with a key for the peer, a segment without a valid signature is discarded silently,
    /// RSTs included. Without a key, a signed segment is discarded too, since we cannot check it.
    /// </summary>
    private bool IsAuthentic(TcpSegment segment, TcpOptions options)
    {
        if (_authenticator is null) return options.Authentication is null && options.Md5DigestOffset is null;
        if (State == TcpState.SynSent && segment.Has(TcpFlags.Syn))
            _authenticator.SetInitialSequences(_initialSequence.Value, segment.SequenceNumber);
        var extension = segment.Has(TcpFlags.Syn) ? 0 : SequenceExtension(segment.SequenceNumber, _receiveNext64);
        return _authenticator.Verify(segment, options, extension);
    }

    /// <summary>
    /// SYN-SENT has its own rules (RFC 9293 3.10.7.3), because no receive sequence space exists yet:
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>A bogus ACK draws a RST.</item>
    /// <item>A RST that acknowledges our SYN means "connection refused".</item>
    /// <item>A SYN-ACK completes the handshake.</item>
    /// <item>A bare SYN means both sides opened at once (simultaneous open).</item>
    /// </list>
    /// </remarks>
    private void ReceiveInSynSent(TcpSegment segment, TcpOptions options, bool congestionExperienced)
    {
        if (segment.Has(TcpFlags.Ack) && !AcknowledgesOurSyn(segment))
        {
            _host.Reset(RemoteAddress, segment);
            return;
        }
        if (segment.Has(TcpFlags.Rst))
        {
            if (segment.Has(TcpFlags.Ack)) Fail(TcpMessages.ConnectionRefused);
            return;
        }
        if (!segment.Has(TcpFlags.Syn) || segment.Has(TcpFlags.Fin)) return;
        LearnPeerSyn(segment, options);
        if (segment.Has(TcpFlags.Ack)) CompleteHandshake(segment, options, congestionExperienced);
        else BeginSimultaneousOpen();
    }

    /// <summary>ISS &lt; SEG.ACK &lt;= SND.NXT: covers our SYN and nothing we have not sent.</summary>
    private bool AcknowledgesOurSyn(TcpSegment segment)
    {
        SequenceNumber acknowledgment = segment.AcknowledgmentNumber;
        return !(acknowledgment <= _initialSequence) && !(_sendNext < acknowledgment);
    }

    /// <summary>
    /// Received the SYN-ACK that acknowledges our SYN: take the acknowledgment, learn the Fast Open outcome, become
    /// ESTABLISHED, take any data the SYN-ACK carried, send the handshake's final ACK, and flush anything the
    /// connect callbacks queued.
    /// </summary>
    private void CompleteHandshake(TcpSegment segment, TcpOptions options, bool congestionExperienced)
    {
        ProcessAcknowledgment(segment, options);
        LearnFastOpenReply(segment, options);
        BecomeEstablished();
        if (IsClosed) return;
        if (!segment.Payload.IsEmpty) ReceiveData(segment, congestionExperienced);
        else SendAck();
        Flush();
    }

    /// <summary>Both ends sent SYN at once: answer the peer's SYN by turning ours into a SYN-ACK.</summary>
    private void BeginSimultaneousOpen()
    {
        EnterState(TcpState.SynReceived);
        if (State != TcpState.SynReceived) return;
        var syn = _unacknowledged.Oldest;
        syn.Flags = (syn.Flags | TcpFlags.Ack) & ~(TcpFlags.Ece | TcpFlags.Cwr) | (_ecn ? TcpFlags.Ece : TcpFlags.None);
        Retransmit();
    }

    /// <summary>
    /// In SYN-RECEIVED, the peer's SYN again: its SYN-ACK completing a simultaneous open, or a
    /// retransmitted SYN because our SYN-ACK was lost.
    /// </summary>
    private bool IsPeerSynAgain(TcpSegment segment) =>
        State == TcpState.SynReceived && segment.Has(TcpFlags.Syn) && !segment.Has(TcpFlags.Rst) &&
        segment.SequenceNumber == _peerInitialSequence;

    /// <summary>
    /// A SYN-ACK acknowledging our SYN completes a simultaneous open. A bare SYN means the peer never got our
    /// SYN-ACK, so resend it. Anything else is ignored.
    /// </summary>
    private void ReceivePeerSynAgain(TcpSegment segment, TcpOptions options, bool congestionExperienced)
    {
        if (_activeOpen && segment.Has(TcpFlags.Ack) && segment.AcknowledgmentNumber == _sendNext)
            CompleteHandshake(segment, options, congestionExperienced);
        else if (!segment.Has(TcpFlags.Ack)) Retransmit();
    }

    /// <summary>The peer resent its FIN because our ACK of it was lost.</summary>
    private bool IsRetransmittedFinInTimeWait(TcpSegment segment) =>
        State == TcpState.TimeWait && segment.Has(TcpFlags.Fin) &&
        (SequenceNumber)segment.SequenceNumber + segment.SequenceLength == _receive.Next;

    /// <summary>
    /// Re-acknowledges the peer's FIN and restarts the 2 x MSL wait (RFC 9293 3.10.7.4). TIME-WAIT exists
    /// precisely so this lost final ACK can be repeated.
    /// </summary>
    private void RestartTimeWait()
    {
        _stateDeadline = Now + TimeWaitDuration;
        SendAck();
    }

    /// <summary>
    /// Whether a new SYN may replace this TIME-WAIT connection (RFC 9293 3.10.7.4, RFC 6191): its timestamp is newer
    /// than any the old connection saw, or, without timestamps, its sequence number lies beyond the old stream.
    /// </summary>
    internal bool AcceptsReplacementSyn(TcpSegment syn, TcpOptions options)
    {
        if (State != TcpState.TimeWait) return false;
        if (_timestamps && options.Timestamp is { } timestamp) return unchecked((int)(timestamp.Value - _recentTimestamp)) > 0;
        return _receive.Next < (SequenceNumber)syn.SequenceNumber;
    }

    /// <summary>Whether any of the segment falls in the receive window (RFC 9293 3.10.7.4, first check).</summary>
    private bool IsAcceptable(TcpSegment segment)
    {
        var window = (uint)ReceiveWindow;
        SequenceNumber first = segment.SequenceNumber;
        var length = segment.SequenceLength;
        if (window == 0) return length == 0 && first == _receive.Next;
        if (length == 0) return first.IsWithin(_receive.Next, window);
        return first.IsWithin(_receive.Next, window) || (first + length - 1).IsWithin(_receive.Next, window);
    }

    /// <summary>Data that lies entirely before RCV.NXT: a retransmission of something already received.</summary>
    private bool IsOldDuplicate(TcpSegment segment) =>
        _sackPermitted && !segment.Payload.IsEmpty && !segment.Has(TcpFlags.Syn) &&
        (SequenceNumber)segment.SequenceNumber + (uint)segment.Payload.Length <= _receive.Next;

    /// <summary>
    /// With a zero window no segment carrying data or FIN is acceptable, yet RFC 9293 3.10.7.4 still wants its ACK,
    /// URG and RST honored. A segment starting exactly at RCV.NXT, such as a zero-window probe, gets that allowance;
    /// the text step then buffers none of it and re-acknowledges.
    /// </summary>
    private bool IsAtClosedWindowEdge(TcpSegment segment) =>
        ReceiveWindow == 0 && segment.SequenceNumber == _receive.Next;

    /// <summary>Only an exact-match RST closes the connection; any other in-window RST is challenged (RFC 5961 3).</summary>
    private void ReceiveReset(TcpSegment segment)
    {
        if (segment.SequenceNumber == _receive.Next) Fail(TcpMessages.PeerReset);
        else SendChallengeAck();
    }

    /// <summary>
    /// Replies to a suspicious segment with an ACK stating our true position (RFC 5961). A real peer that lost
    /// sync will answer with an exact RST or resynchronize; a blind attacker learns nothing. Rate-limited.
    /// </summary>
    private void SendChallengeAck()
    {
        if (_challengeAcks.TryAcquire(Now)) SendAck();
    }

    /// <summary>
    /// The ACK step of segment processing. In SYN-RECEIVED, an ACK within SND.UNA &lt; SEG.ACK &lt;= SND.NXT completes a
    /// passive open, and any other ACK draws a RST. Otherwise an ACK for data never sent is challenged, and the
    /// rest update send state.
    /// </summary>
    /// <returns>False when the rest of the segment must be ignored.</returns>
    private bool ReceiveAcknowledgment(TcpSegment segment, TcpOptions options)
    {
        SequenceNumber acknowledgment = segment.AcknowledgmentNumber;
        if (State == TcpState.SynReceived)
        {
            if (acknowledgment <= _sendUnacknowledged || _sendNext < acknowledgment)
            {
                _host.Reset(RemoteAddress, segment);
                return false;
            }
            ProcessAcknowledgment(segment, options);
            BecomeEstablished();
            return true;
        }
        if (_sendNext < acknowledgment)
        {
            // Acknowledges data we never sent (RFC 5961 5).
            SendChallengeAck();
            return false;
        }
        ProcessAcknowledgment(segment, options);
        return true;
    }

    /// <summary>
    /// The URG step: record how far urgent data extends and notify the application when that point moves forward.
    /// Urgent bytes are still delivered inline in the normal stream; only the marker is extra.
    /// </summary>
    private void ReceiveUrgentPointer(TcpSegment segment)
    {
        if (!segment.Has(TcpFlags.Urg) || segment.UrgentPointer == 0 || PeerClosed) return;
        var end = (SequenceNumber)segment.SequenceNumber + segment.UrgentPointer;
        if (UrgentDataEnd is { } current && (SequenceNumber)current >= end) return;
        UrgentDataEnd = end.Value;
        UrgentDataAvailable?.Invoke(this);
    }

    /// <summary>
    /// The text and FIN steps. Data or FIN is buffered while the peer's stream is still open. After its FIN, any
    /// further sequence-consuming segment is a retransmission and just gets re-acknowledged.
    /// </summary>
    private void ReceiveStreamContent(TcpSegment segment, bool congestionExperienced)
    {
        var carriesStream = segment.Payload.Length > 0 || segment.Has(TcpFlags.Fin);
        if (carriesStream && !PeerClosed) ReceiveData(segment, congestionExperienced);
        else if (segment.SequenceLength > 0) SendAck();
    }

    /// <summary>
    /// Hands payload and FIN to the <see cref="ReceiveBuffer"/>, acknowledges per the delayed-ACK policy, then raises
    /// <see cref="DataAvailable"/> and <see cref="ReadClosed"/>. Events are skipped once a callback has failed the
    /// connection. Data arriving after <see cref="CloseRead"/> resets the connection.
    /// </summary>
    private void ReceiveData(TcpSegment segment, bool congestionExperienced)
    {
        if (_readClosed && !segment.Payload.IsEmpty)
        {
            ResetForDiscardedData();
            return;
        }
        var readableBefore = _receive.Available;
        var nextBefore = _receive.Next;
        var start = (SequenceNumber)segment.SequenceNumber + (segment.Has(TcpFlags.Syn) ? TcpWireFormat.ControlSequenceLength : 0);
        var outcome = _receive.Accept(start, segment.Payload.Span, segment.Has(TcpFlags.Fin), ReceiveWindow);
        _receiveNext64 += _receive.Next - nextBefore;
        // A peer still sending into our half-close has not abandoned the connection.
        if (State == TcpState.FinWait2) _stateDeadline = Now + FinWait2Timeout;
        if (outcome.StreamEnded) PeerFinReached();
        if (FailureReason is not null) return;
        if (_ecn && congestionExperienced) _ecnEcho = true;
        AcknowledgeData(segment, outcome, congestionExperienced, advanced: _receive.Next != nextBefore);
        if (_receive.Available > readableBefore && !_readClosed) DataAvailable?.Invoke(this);
        if (outcome.StreamEnded && FailureReason is null) ReadClosed?.Invoke(this);
    }

    /// <summary>
    /// Delayed ACKs (RFC 1122 4.2.3.2, RFC 5681 4.2): acknowledge at least every second full-sized segment, and
    /// within <see cref="TcpSettings.DelayedAckTimeout"/> otherwise. Acknowledge at once when the ACK carries news the
    /// sender needs promptly: out-of-order data or a filled hole (for fast retransmit and SACK), duplicates
    /// (D-SACK), data that did not advance RCV.NXT, the peer's FIN, ECN congestion marks, and a window that just
    /// closed (so the sender starts probing rather than retransmitting).
    /// </summary>
    private void AcknowledgeData(TcpSegment segment, ReceiveOutcome outcome, bool congestionExperienced, bool advanced)
    {
        _largestReceivedSegment = Math.Max(_largestReceivedSegment, segment.Payload.Length);
        var immediate = !_settings.DelayedAcknowledgments || !advanced || outcome.OutOfOrder || outcome.FilledGap ||
                        outcome.Duplicate || outcome.StreamEnded || congestionExperienced || _receive.HasOutOfOrderData ||
                        ReceiveWindow == 0;
        _bytesSinceAck += segment.Payload.Length;
        if (immediate || _bytesSinceAck >= 2 * _largestReceivedSegment)
        {
            SendAck();
            return;
        }
        if (_ackPending) return;
        _ackPending = true;
        _ackDeadline = Now + _settings.DelayedAckTimeout;
    }

    /// <summary>Any segment carrying an ACK satisfies a pending delayed ACK and becomes Last.ACK.sent for timestamps.</summary>
    private void NoteAcknowledgmentSent()
    {
        _ackPending = false;
        _bytesSinceAck = 0;
        _lastAcknowledgmentSent = _receive.Next;
    }
}
