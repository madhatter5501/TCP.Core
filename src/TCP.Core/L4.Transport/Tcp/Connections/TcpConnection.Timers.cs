using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>State deadlines, acknowledgment delay, keep-alive, probing and retransmission timeouts, driven by the host's tick.</summary>
public sealed partial class TcpConnection
{
    private const int MaximumConsecutiveTimeouts = 8;
    private const int BlackHoleTimeouts = 2; // Consecutive timeouts of full-sized segments before trying smaller ones.

    /// <summary>
    /// Runs whichever timers are due, driven by <see cref="TcpHost"/>'s tick. In priority order:
    /// </summary>
    /// <remarks>
    /// <list type="number">
    /// <item>The TIME-WAIT end and the FIN-WAIT-2 give-up.</item>
    /// <item>The user timeout and keep-alive, which can end the connection.</item>
    /// <item>A delayed ACK that has waited long enough.</item>
    /// <item>Raising a lowered path MTU again.</item>
    /// <item>Zero-window probing, which replaces retransmission while the peer's window is shut.</item>
    /// <item>RACK's reorder timer, the tail loss probe, and the retransmission timeout.</item>
    /// </list>
    /// <para>Then it flushes, in case something became sendable.</para>
    /// </remarks>
    internal void Tick()
    {
        if (IsClosed) return;
        if (State == TcpState.TimeWait)
        {
            if (Now >= _stateDeadline) EnterState(TcpState.Closed);
            return;
        }
        if (State == TcpState.FinWait2 && Now >= _stateDeadline)
        {
            Fail(TcpMessages.FinWait2Expired);
            return;
        }
        if (UserTimeoutExpired)
        {
            Fail(TcpMessages.UserTimeoutExpired);
            return;
        }
        KeepAliveIfDue();
        if (IsClosed) return;
        if (_ackPending && Now >= _ackDeadline) SendAck();
        RaisePathMtuIfDue();
        if (IsBlockedByZeroWindow)
        {
            ProbeZeroWindowIfDue();
            return;
        }
        if (_reorderTimer is { } reorder && Now >= reorder) ReorderTimeout();
        if (_tailLossProbe.Deadline is { } probe && Now >= probe && Now < _retransmitAt) SendTailLossProbe();
        if (!_unacknowledged.IsEmpty && Now >= _retransmitAt) RetransmissionTimeout();
        Flush();
    }

    /// <summary>The peer's window is shut while we have data or a FIN to deliver: the case the persist timer exists for.</summary>
    private bool IsBlockedByZeroWindow => _sendWindow.Size == 0 && !IsSynchronizing && HasSomethingToSend;

    /// <summary>Unsent bytes, bytes awaiting acknowledgment, or a FIN still to send.</summary>
    private bool HasSomethingToSend =>
        _unsent.Count > 0 || !_unacknowledged.IsEmpty || (_closeRequested && SendSideOpen);

    /// <summary>
    /// RFC 9293 3.8.3 and RFC 5482: data has waited for acknowledgment, without any progress, longer than the user
    /// timeout. Progress means SND.UNA advancing; the clock starts when data goes out with nothing else in flight.
    /// </summary>
    private bool UserTimeoutExpired =>
        _userTimeout is { } timeout && HasSomethingToSend && !_unacknowledged.IsEmpty && Now - _lastProgress >= timeout;

    /// <summary>
    /// Keep-alive (RFC 1122 4.2.3.6): after <see cref="TcpSettings.KeepAliveIdle"/> with nothing received and
    /// nothing outstanding, send an ACK for SND.NXT - 1. It lies below the peer's window, so a live peer must answer
    /// with an ACK; a dead or rebooted one stays silent or resets. Unanswered probes repeat every
    /// <see cref="TcpSettings.KeepAliveInterval"/> until the limit fails the connection.
    /// </summary>
    private void KeepAliveIfDue()
    {
        if (!KeepAlive || State is not (TcpState.Established or TcpState.CloseWait)) return;
        if (!_unacknowledged.IsEmpty || _unsent.Count > 0) return;
        var due = _lastReceived + _settings.KeepAliveIdle + _settings.KeepAliveInterval * _keepAliveProbes;
        if (Now < due) return;
        if (_keepAliveProbes >= _settings.KeepAliveProbes)
        {
            Fail(TcpMessages.KeepAliveExpired);
            return;
        }
        _keepAliveProbes++;
        SendSegment(_sendNext - 1, TcpFlags.Ack, []);
    }

    /// <summary>
    /// RFC 1191 6.3: a lowered path MTU may have been temporary, so after <see cref="TcpSettings.PathMtuRaiseInterval"/>
    /// try the route's full MTU again. If the path is still narrow, ICMP or black-hole detection lowers it again.
    /// </summary>
    private void RaisePathMtuIfDue()
    {
        if (_pathMtuLoweredAt is not { } lowered || Now - lowered < _settings.PathMtuRaiseInterval) return;
        _pathMtu = IPv4Packet.MaximumTotalLength;
        _pathMtuLoweredAt = null;
    }

    /// <summary>Sends the next zero-window probe when its backoff delay has passed, or fails the connection after too many go unanswered.</summary>
    private void ProbeZeroWindowIfDue()
    {
        if (!_persist.IsDue(Now)) return;
        if (_persist.ProbesExhausted)
        {
            Fail(TcpMessages.ProbeLimitExceeded);
            return;
        }
        _persist.ProbeSent(Now);
        SendWindowProbe();
    }

    /// <summary>
    /// Probes with one new byte if nothing is in flight, else the first unacknowledged byte, else a
    /// bare ACK for already-acknowledged sequence space; each forces the peer to report its window.
    /// </summary>
    private void SendWindowProbe()
    {
        if (_unacknowledged.IsEmpty && _unsent.Count > 0)
        {
            Transmit(TcpFlags.Ack, _unsent.Dequeue(1));
        }
        else if (!_unacknowledged.IsEmpty && _unacknowledged.Oldest.Data.Length > 0)
        {
            var oldest = _unacknowledged.Oldest;
            oldest.Retransmitted = true;
            Retransmissions++;
            SendSegment(oldest.Sequence, TcpFlags.Ack, [oldest.Data[0]], retransmission: true);
        }
        else
        {
            SendSegment(_sendNext - 1, TcpFlags.Ack, []);
        }
    }

    /// <summary>
    /// RFC 5681 3.1 and RFC 6298 5.5: collapse cwnd, back off the timer and resend from SND.UNA. Also:
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>A SYN that times out drops its ECN request and any Fast Open data, in case a middlebox discards them
    /// (RFC 3168 6.1.1.1, RFC 7413 4.1.3).</item>
    /// <item>Repeated timeouts of full-sized segments suggest a path MTU black hole (RFC 2923): retry smaller
    /// (RFC 4821).</item>
    /// <item>With timestamps, remember the retransmission's TSval so Eifel detection can spot a spurious timeout.</item>
    /// </list>
    /// </remarks>
    private void RetransmissionTimeout()
    {
        if (++_consecutiveTimeouts > MaximumConsecutiveTimeouts)
        {
            Fail(TcpMessages.RetransmissionLimitExceeded);
            return;
        }
        if (State == TcpState.SynSent) SimplifyRetransmittedSyn();
        else if (!IsSynchronizing) DetectBlackHole();
        if (!IsSynchronizing) _congestion.OnRetransmissionTimeout(FlightSize, MaximumSegmentSize, Now);
        _rtt.BackOff();
        _inRecovery = false;
        _timeoutRecoveryPoint = _ecnReductionPoint = _sendNext;
        _duplicateAcks = 0;
        _reorderTimer = null;
        _tailLossProbe.Reset();
        _unacknowledged.MarkAllLost();
        Retransmit();
        if (_timestamps && !_unacknowledged.IsEmpty && _consecutiveTimeouts == 1)
            _timeoutRetransmitTimestamp = _unacknowledged.Oldest.TimestampValue;
    }

    /// <summary>
    /// A SYN that went unanswered is resent plain: without the ECN request, and with Fast Open data split off to be
    /// sent after the handshake.
    /// </summary>
    private void SimplifyRetransmittedSyn()
    {
        var syn = _unacknowledged.Oldest;
        if (syn.Has(TcpFlags.Ece))
        {
            syn.Flags &= ~(TcpFlags.Ece | TcpFlags.Cwr);
            _ecnRequested = false;
        }
        if (syn.Data.Length == 0 || _unacknowledged.Count > 1) return;
        _unacknowledged.Add(syn.SplitAt(0));
        _fastOpenDataSent = false;
    }

    /// <summary>
    /// Black-hole detection (RFC 4821, RFC 2923): when full-sized segments keep timing out, routers may be dropping
    /// them without sending "fragmentation needed". Halve the path MTU, down to the 576-byte minimum every IPv4 host
    /// must accept; <see cref="RaisePathMtuIfDue"/> tries the larger size again later.
    /// </summary>
    private void DetectBlackHole()
    {
        if (!_settings.BlackHoleDetection || _consecutiveTimeouts < BlackHoleTimeouts || _unacknowledged.IsEmpty) return;
        var mtu = BaseSegmentSize + TcpWireFormat.IPv4AndTcpHeaderLength;
        if (mtu <= IPv4Constants.MinimumReassemblyLength || _unacknowledged.Oldest.Data.Length < MaximumSegmentSize) return;
        LowerPathMtu(Math.Max(IPv4Constants.MinimumReassemblyLength, mtu / 2));
    }
}
