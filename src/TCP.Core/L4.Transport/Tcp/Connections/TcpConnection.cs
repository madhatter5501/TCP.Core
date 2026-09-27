using System.Net;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp.Authentication;
using TCP.L4.Transport.Tcp.Buffers;
using TCP.L4.Transport.Tcp.Congestion;
using TCP.L4.Transport.Tcp.Reliability;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>A bounded, full-duplex byte stream. APIs and callbacks run on the IPv4 receive/timer thread.</summary>
/// <remarks>
/// <para>
/// One endpoint of a TCP connection: the protocol engine of the transport layer. Applications see an ordered,
/// reliable, flow-controlled byte stream (<see cref="Send"/>, <see cref="Read"/> and the events). Underneath it
/// runs the RFC 9293 state machine, sequence numbering and acknowledgment, retransmission (<see cref="RttEstimator"/>,
/// <see cref="RetransmissionQueue"/>, <see cref="RecentAcknowledgment"/>, <see cref="TailLossProbe"/>), flow control
/// (<see cref="SendWindow"/>, <see cref="ReceiveBuffer"/>), and congestion control (<see cref="CongestionController"/>).
/// </para>
/// <para>
/// <see cref="TcpHost"/> creates connections, feeds them segments and ticks, and carries their segments to IP.
/// </para>
/// <para>
/// This file holds the application API and state transitions. Option negotiation lives in
/// <c>TcpConnection.Options.cs</c>, segment arrival in <c>TcpConnection.Receiving.cs</c>, loss recovery in
/// <c>TcpConnection.Recovery.cs</c>, transmission in <c>TcpConnection.Sending.cs</c> and timeouts in
/// <c>TcpConnection.Timers.cs</c>. Application callbacks may abort the connection synchronously, so code that
/// raises one re-checks <see cref="IsClosed"/> before carrying on.
/// </para>
/// </remarks>
public sealed partial class TcpConnection
{
    /// <summary>Most bytes <see cref="Send"/> will hold, unsent plus unacknowledged, before accepting fewer than offered.</summary>
    public const int MaximumSendBuffer = 4_194_304;
    /// <summary>RFC 9293 3.8.6.3: an ACK must not be delayed longer than 0.5 seconds.</summary>
    internal static readonly TimeSpan MaximumDelayedAckTimeout = TimeSpan.FromMilliseconds(500);
    // TIME-WAIT lasts 2 x MSL (RFC 9293); MSL is the IPv4 maximum datagram lifetime.
    private static readonly TimeSpan TimeWaitDuration = IPv4Constants.MaximumDatagramLifetime * 2;
    // Gives up on a peer that goes silent after acknowledging our FIN; each data segment it sends restarts the wait.
    private static readonly TimeSpan FinWait2Timeout = TimeSpan.FromMinutes(5);

    private readonly TcpHost _host;
    private readonly TcpSettings _settings;
    private readonly SequenceNumber _initialSequence; // ISS
    private SequenceNumber _peerInitialSequence; // IRS
    private SequenceNumber _sendUnacknowledged; // SND.UNA
    private SequenceNumber _sendNext; // SND.NXT
    private readonly ByteQueue _unsent = new();
    private readonly RetransmissionQueue _unacknowledged = new();
    private readonly ReceiveBuffer _receive;
    private readonly SendWindow _sendWindow = new();
    private readonly CongestionController _congestion;
    private readonly RttEstimator _rtt = new();
    private readonly PersistTimer _persist = new();
    private readonly ChallengeAckLimiter _challengeAcks = new();
    private readonly RecentAcknowledgment _rack = new();
    private readonly TailLossProbe _tailLossProbe = new();
    private readonly SegmentAuthenticator? _authenticator;
    private ushort _peerMss = TcpWireFormat.DefaultIPv4Mss;
    private int _pathMtu = IPv4Packet.MaximumTotalLength;
    private DateTimeOffset? _pathMtuLoweredAt;
    private bool _activeOpen;
    private bool _closeRequested;
    private bool _readClosed;
    private bool _flushing;
    private bool _acceptNotified;
    private DateTimeOffset _retransmitAt;
    private DateTimeOffset _stateDeadline;
    private int _consecutiveTimeouts;
    private SequenceNumber? _sendUrgentEnd;
    private DateTimeOffset _lastReceived;
    private DateTimeOffset _lastSent;
    private DateTimeOffset _lastProgress;
    private int _keepAliveProbes;
    private TimeSpan? _userTimeout;
    private bool _advertiseUserTimeout;
    private SequenceNumber? _userTimeoutCarriedThrough;

    /// <summary>
    /// Creates a connection in CLOSED. Only <see cref="TcpHost"/> constructs connections, and immediately
    /// starts the handshake with <see cref="Open"/>, <see cref="AcceptSyn"/> or <see cref="AcceptCookie"/>.
    /// </summary>
    /// <param name="host">The transport layer that routes segments to and from this connection.</param>
    /// <param name="localPort">Our port.</param>
    /// <param name="remoteAddress">The peer's IPv4 address.</param>
    /// <param name="remotePort">The peer's port.</param>
    /// <param name="initialSequence">Our ISN, from <see cref="InitialSequenceNumberGenerator"/>.</param>
    /// <param name="receiveCapacity">Receive buffer size, which caps the window we offer.</param>
    /// <param name="listener">The accepting listener for a passive open; null for an active one.</param>
    internal TcpConnection(TcpHost host, ushort localPort, IPAddress remoteAddress, ushort remotePort,
        uint initialSequence, int receiveCapacity, TcpListener? listener)
    {
        _host = host;
        _settings = host.Settings;
        LocalPort = localPort;
        RemoteAddress = remoteAddress;
        RemotePort = remotePort;
        _initialSequence = _sendUnacknowledged = _sendNext = initialSequence;
        _sendNext64 = initialSequence;
        _receive = new ReceiveBuffer(receiveCapacity);
        _receiveScale = WindowScaleFor(receiveCapacity);
        _congestion = CongestionController.Create(_settings.CongestionControl);
        _timestampOffset = host.TimestampOffset(new ConnectionKey(localPort, remoteAddress, remotePort));
        Listener = listener;
        KeepAlive = _settings.KeepAlive;
        _userTimeout = _settings.UserTimeout;
        _advertiseUserTimeout = _userTimeout is not null;
        _lastReceived = _lastSent = _lastProgress = Now;
        var keys = host.AuthenticationKeysFor(remoteAddress, localPort, remotePort);
        if (keys.Count == 0) return;
        _authenticator = new SegmentAuthenticator(keys, host.Address, remoteAddress, localPort, remotePort);
        _authenticator.SetInitialSequences(initialSequence, 0);
    }

    /// <summary>Current RFC 9293 state; changes are announced through <see cref="StateChanged"/>.</summary>
    public TcpState State { get; private set; } = TcpState.Closed;

    /// <summary>Our port.</summary>
    public ushort LocalPort { get; }

    /// <summary>The peer's IPv4 address.</summary>
    public IPAddress RemoteAddress { get; }

    /// <summary>The peer's port.</summary>
    public ushort RemotePort { get; }

    /// <summary>In-order bytes ready for <see cref="Read"/>.</summary>
    public int Available => _readClosed ? 0 : _receive.Available;

    /// <summary>Bytes accepted by <see cref="Send"/> but not yet acknowledged by the peer, whether sent or still queued.</summary>
    public int BufferedSendBytes => _unsent.Count + _unacknowledged.BufferedBytes;

    /// <summary>The peer has sent FIN and every byte before it has arrived: the read side has reached end of stream.</summary>
    public bool PeerClosed { get; private set; }

    /// <summary>Why the connection closed abnormally (reset, timeout, abort, unreachable), or null.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Disables Nagle's algorithm, so small writes go out at once instead of waiting for outstanding data to be acknowledged.</summary>
    public bool NoDelay { get; set; }

    /// <summary>Send keep-alive probes when the connection is idle (RFC 1122 4.2.3.6), and fail it if they go unanswered.</summary>
    /// <remarks>Timing comes from <see cref="TcpSettings.KeepAliveIdle"/>, <see cref="TcpSettings.KeepAliveInterval"/> and <see cref="TcpSettings.KeepAliveProbes"/>.</remarks>
    public bool KeepAlive { get; set; }

    /// <summary>
    /// How long sent data may remain unacknowledged before the connection is aborted (RFC 9293 3.8.3), or null for
    /// no limit beyond the retransmission count. Setting it also advertises it to the peer (RFC 5482).
    /// </summary>
    public TimeSpan? UserTimeout
    {
        get => _userTimeout;
        set
        {
            if (value is { } timeout && timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(value));
            _userTimeout = value;
            _advertiseUserTimeout = value is not null;
            _userTimeoutCarriedThrough = null;
        }
    }

    /// <summary>The most recent ICMP error that matched this connection, for diagnostics; it may not have been fatal.</summary>
    public string? LastNetworkError { get; private set; }

    /// <summary>Sequence immediately after the latest indicated urgent data. Bytes are delivered inline.</summary>
    public uint? UrgentDataEnd { get; private set; }

    /// <summary>Offered receive window (RCV.WND) in bytes, before window scaling rounds it for the header.</summary>
    public int ReceiveWindow => _receive.Window(MaximumSegmentSize);

    /// <summary>SND.NXT: sequence number of the next new byte we will send. Exposed for diagnostics.</summary>
    public uint NextSendSequence => _sendNext.Value;

    /// <summary>RCV.NXT: next sequence number expected from the peer. Exposed for diagnostics.</summary>
    public uint NextReceiveSequence => _receive.Next.Value;

    /// <summary>Current retransmission timeout (RTO) in seconds, as estimated from measured round trips.</summary>
    public double RetransmissionTimeoutSeconds => _rtt.TimeoutSeconds;

    /// <summary>Smoothed round-trip time, or null before the first measurement.</summary>
    public TimeSpan? SmoothedRoundTripTime => _rtt.SmoothedRtt;

    /// <summary>Congestion window in bytes: how much the network is judged able to carry in flight.</summary>
    public double CongestionWindow => _congestion.Window;

    /// <summary>Slow-start threshold in bytes.</summary>
    public double SlowStartThreshold => _congestion.SlowStartThreshold;

    /// <summary>Count of segments resent, including probes that resend a byte; a rough loss indicator.</summary>
    public int Retransmissions { get; private set; }

    /// <summary>Retransmissions later shown unnecessary by timestamps (RFC 3522) and undone.</summary>
    public int SpuriousRetransmissionTimeouts { get; private set; }

    /// <summary>
    /// Largest payload we put in one segment (RFC 9293 3.7.1's Eff.snd.MSS): the smallest of the peer's advertised
    /// MSS, our route's MSS, and the path MTU learned from ICMP or black-hole detection, minus headers and the
    /// options every segment carries (timestamps, authentication).
    /// </summary>
    public int MaximumSegmentSize => Math.Max(1, BaseSegmentSize - FixedOptionLength);

    /// <summary>The handshake completed and the connection is ESTABLISHED.</summary>
    public event Action<TcpConnection>? Connected;

    /// <summary>New in-order bytes can be read with <see cref="Read"/>.</summary>
    public event Action<TcpConnection>? DataAvailable;

    /// <summary>The peer finished sending (FIN received in order); <see cref="PeerClosed"/> is now true.</summary>
    public event Action<TcpConnection>? ReadClosed;

    /// <summary>The peer acknowledged data, freeing send-buffer space; a good moment to <see cref="Send"/> more.</summary>
    public event Action<TcpConnection>? SendReady;

    /// <summary>The peer signalled urgent data ending at <see cref="UrgentDataEnd"/>.</summary>
    public event Action<TcpConnection>? UrgentDataAvailable;

    /// <summary>Raised on every state transition, including the final one to <see cref="TcpState.Closed"/>.</summary>
    public event Action<TcpConnection, TcpState>? StateChanged;

    /// <summary>The listener that accepted this connection, or null if we opened it; <see cref="TcpHost"/> uses it for backlog accounting.</summary>
    internal TcpListener? Listener { get; }

    /// <summary>Current time from the host's clock; fake in tests.</summary>
    private DateTimeOffset Now => _host.Time.GetUtcNow();

    /// <summary>Terminal state: nothing may be sent or processed any more.</summary>
    private bool IsClosed => State == TcpState.Closed;

    /// <summary>Still in the three-way handshake.</summary>
    private bool IsSynchronizing => State is TcpState.SynSent or TcpState.SynReceived;

    /// <summary>
    /// Our direction of the stream is open: we have not yet sent a FIN. A server that accepted Fast Open data may
    /// answer while still in SYN-RECEIVED (RFC 7413 4.2.2).
    /// </summary>
    private bool SendSideOpen => State is TcpState.Established or TcpState.CloseWait || (State == TcpState.SynReceived && FastOpenAccepted);

    /// <summary>Bytes sent but not yet acknowledged (SND.NXT - SND.UNA).</summary>
    private uint FlightSize => _sendNext - _sendUnacknowledged;

    /// <summary>The per-route segment budget before per-segment options: min(peer MSS, route MSS, path MTU - 40).</summary>
    private int BaseSegmentSize =>
        Math.Min(Math.Min(_peerMss, _host.SendMss(RemoteAddress)), _pathMtu - TcpWireFormat.IPv4AndTcpHeaderLength);

    /// <summary>Copies up to the free send-buffer capacity. Return value is the byte count accepted, not delivered.</summary>
    /// <remarks>
    /// Bytes are queued and sent as the windows allow, possibly immediately. When the buffer is full, wait for
    /// <see cref="SendReady"/> and offer the rest.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Not ESTABLISHED or CLOSE-WAIT, or <see cref="Close"/> was already called.</exception>
    public int Send(ReadOnlySpan<byte> bytes)
    {
        if (_closeRequested || !SendSideOpen) throw new InvalidOperationException(TcpMessages.NotWritable);
        var count = Math.Min(bytes.Length, MaximumSendBuffer - BufferedSendBytes);
        _unsent.Enqueue(bytes[..count]);
        Flush();
        return count;
    }

    /// <summary>
    /// Sends <paramref name="bytes"/> as urgent data (RFC 9293 3.8.5): the urgent pointer of every segment until they
    /// are acknowledged marks the byte after the last of them, so the peer can skip ahead to it. The bytes travel
    /// inline in the stream and bypass Nagle's algorithm.
    /// </summary>
    /// <returns>The byte count accepted; the urgent mark covers only accepted bytes.</returns>
    /// <exception cref="InvalidOperationException">Not open for writing.</exception>
    public int SendUrgent(ReadOnlySpan<byte> bytes)
    {
        if (_closeRequested || !SendSideOpen) throw new InvalidOperationException(TcpMessages.NotWritable);
        var count = Math.Min(bytes.Length, MaximumSendBuffer - BufferedSendBytes);
        _unsent.Enqueue(bytes[..count]);
        if (count > 0) _sendUrgentEnd = _sendNext + (uint)_unsent.Count;
        Flush();
        return count;
    }

    /// <summary>Reads available stream bytes. Zero means no buffered bytes; PeerClosed distinguishes EOF.</summary>
    /// <remarks>Reading frees receive-buffer space. If that lets the offered window grow, a window update ACK is sent so the peer can resume.</remarks>
    public int Read(Span<byte> destination)
    {
        if (_readClosed) return 0;
        var count = _receive.Read(destination);
        if (count > 0 && WindowUpdateWorthSending) SendAck();
        return count;
    }

    /// <summary>Half-closes writing after queued bytes; reading remains possible until the peer sends FIN.</summary>
    /// <remarks>
    /// The FIN is sent once every queued byte is out, which moves the state to FIN-WAIT-1 or LAST-ACK. During the
    /// handshake there is nothing to close gracefully, so the connection is aborted instead. Later calls do nothing.
    /// Call <see cref="CloseRead"/> as well for a full close that resets the peer if its data would be lost.
    /// </remarks>
    public void Close()
    {
        if (IsSynchronizing && !FastOpenAccepted)
        {
            Abort();
            return;
        }
        if (!SendSideOpen) return;
        _closeRequested = true;
        Flush();
    }

    /// <summary>
    /// The application will read no more. Unread bytes, or data that arrives later, would be silently lost, so the
    /// connection is reset instead to tell the peer (RFC 1122 4.2.2.13, RFC 2525 2.17). With <see cref="Close"/>
    /// this is a full-duplex close; on its own it shuts down only the read side.
    /// </summary>
    public void CloseRead()
    {
        if (_readClosed || IsClosed) return;
        _readClosed = true;
        if (_receive.Available > 0 || _receive.HasOutOfOrderData) ResetForDiscardedData();
    }

    /// <summary>
    /// Tears the connection down at once: sends RST (except from TIME-WAIT, where the peer is already done),
    /// discards all buffered data both ways, and enters CLOSED with <see cref="FailureReason"/> set.
    /// </summary>
    public void Abort()
    {
        if (IsClosed) return;
        if (State != TcpState.TimeWait) SendSegment(_sendNext, TcpFlags.Rst | TcpFlags.Ack, []);
        Fail(TcpMessages.LocallyAborted);
    }

    /// <summary>
    /// Active open, step one of the three-way handshake: send our SYN, with any negotiated options, and enter SYN-SENT.
    /// With a cached Fast Open cookie, queued data rides on the SYN (RFC 7413).
    /// </summary>
    internal void Open()
    {
        _activeOpen = true;
        EnterState(TcpState.SynSent);
        Transmit(SynFlags(), TakeFastOpenData());
    }

    /// <summary>Queues data passed to <see cref="TcpHost.Connect"/> before the SYN goes out, so Fast Open can carry it.</summary>
    internal void QueueInitialData(ReadOnlySpan<byte> bytes) => _unsent.Enqueue(bytes[..Math.Min(bytes.Length, MaximumSendBuffer)]);

    /// <summary>
    /// Passive open, step two of the handshake: learn from the peer's SYN, answer with SYN-ACK, and enter
    /// SYN-RECEIVED. Data on the SYN is queued (RFC 9293 3.10.7.2); with a valid Fast Open cookie it is acknowledged
    /// and handed to the application at once.
    /// </summary>
    internal void AcceptSyn(TcpSegment syn, TcpOptions options, FastOpenRequest fastOpen)
    {
        LearnPeerSyn(syn, options);
        EnterState(TcpState.SynReceived);
        if (IsClosed) return;
        _fastOpen = fastOpen;
        if (!fastOpen.RefusesData && !syn.Payload.IsEmpty) BufferSynData(syn);
        Transmit(SynFlags(), []);
        if (!FastOpenAccepted || IsClosed) return;
        NotifyAccepted();
        if (!IsClosed && Available > 0) DataAvailable?.Invoke(this);
    }

    /// <summary>
    /// Completes a SYN-cookie handshake (RFC 4987 3.6): the final ACK proved the peer received our stateless SYN-ACK,
    /// so rebuild the connection from what the cookie recorded and continue as if it had been in SYN-RECEIVED.
    /// </summary>
    internal void AcceptCookie(TcpSegment ack, TcpOptions options, Handshake.SynCookie cookie, bool congestionExperienced)
    {
        // Our SYN-ACK was never queued, so its ACK moves SND.UNA from ISS to ISS + 1 like any other.
        _sendNext = _initialSequence + TcpWireFormat.ControlSequenceLength;
        _sendNext64 = _sendNext.Value;
        LearnCookie(ack, options, cookie);
        EnterState(TcpState.SynReceived);
        if (!IsClosed) Receive(ack, congestionExperienced);
    }

    /// <summary>
    /// Leaves TIME-WAIT early because the peer opened a new connection on the same four-tuple with a SYN that
    /// cannot be confused with the old one (RFC 9293 3.10.7.4, RFC 6191).
    /// </summary>
    /// <returns>SND.NXT of the old connection, which the new connection's ISN must exceed.</returns>
    internal uint ReplaceInTimeWait()
    {
        var sendNext = _sendNext.Value;
        EnterState(TcpState.Closed);
        return sendNext;
    }

    /// <summary>Reading freed buffer space; tell the peer only when the offered right edge actually moves.</summary>
    private bool WindowUpdateWorthSending =>
        State is not (TcpState.Closed or TcpState.SynSent) && _receive.AdvertisedEdgeWouldMove(MaximumSegmentSize);

    /// <summary>
    /// Enters ESTABLISHED and tells the application: the listener's accept callback first (passive open, unless
    /// Fast Open already announced it), then <see cref="Connected"/>, then any data queued from the SYN. Each
    /// callback may abort, so each step checks the connection is still open.
    /// </summary>
    private void BecomeEstablished()
    {
        EnterState(TcpState.Established);
        if (IsClosed) return;
        NotifyAccepted();
        if (IsClosed) return;
        Connected?.Invoke(this);
        if (!IsClosed && !FastOpenAccepted && Available > 0) DataAvailable?.Invoke(this);
    }

    /// <summary>Raises the listener's accept callback once.</summary>
    private void NotifyAccepted()
    {
        if (_acceptNotified) return;
        _acceptNotified = true;
        Listener?.Accepted(this);
    }

    /// <summary>
    /// The peer acknowledged our FIN, so our direction is fully closed:
    /// FIN-WAIT-1 → FIN-WAIT-2, CLOSING → TIME-WAIT, LAST-ACK → CLOSED.
    /// </summary>
    private void OurFinAcknowledged()
    {
        switch (State)
        {
            case TcpState.FinWait1: EnterState(TcpState.FinWait2); break;
            case TcpState.Closing: EnterState(TcpState.TimeWait); break;
            case TcpState.LastAck: EnterState(TcpState.Closed); break;
        }
    }

    /// <summary>
    /// The peer's FIN arrived in order, so its direction is closed:
    /// ESTABLISHED → CLOSE-WAIT, FIN-WAIT-1 → CLOSING, FIN-WAIT-2 → TIME-WAIT.
    /// </summary>
    private void PeerFinReached()
    {
        PeerClosed = true;
        switch (State)
        {
            case TcpState.Established: EnterState(TcpState.CloseWait); break;
            case TcpState.FinWait1: EnterState(TcpState.Closing); break;
            case TcpState.FinWait2: EnterState(TcpState.TimeWait); break;
        }
    }

    /// <summary>Resets the connection because the application stopped reading while data was, or kept, arriving.</summary>
    private void ResetForDiscardedData()
    {
        SendSegment(_sendNext, TcpFlags.Rst | TcpFlags.Ack, []);
        Fail(TcpMessages.ReceivedDataDiscarded);
    }

    /// <summary>
    /// Ends the connection abnormally: records why, discards unread data so the application sees no more of a
    /// broken stream, and enters CLOSED. Sends nothing; callers decide whether a RST is due.
    /// </summary>
    private void Fail(string reason)
    {
        FailureReason = reason;
        _receive.DiscardReadable();
        EnterState(TcpState.Closed);
    }

    /// <summary>
    /// The single place state changes. Starts the TIME-WAIT or FIN-WAIT-2 deadline, releases resources on
    /// CLOSED, then raises <see cref="StateChanged"/>. A repeat of the current state is ignored.
    /// </summary>
    private void EnterState(TcpState state)
    {
        if (State == state) return;
        State = state;
        if (state == TcpState.TimeWait) _stateDeadline = Now + TimeWaitDuration;
        if (state == TcpState.FinWait2) _stateDeadline = Now + FinWait2Timeout;
        if (state == TcpState.Closed) ReleaseResources();
        StateChanged?.Invoke(this, state);
    }

    /// <summary>
    /// On CLOSED: unregister from the host, freeing the four-tuple, and drop send-side and out-of-order data.
    /// Readable data stays, so after a graceful close the application can still drain it.
    /// </summary>
    private void ReleaseResources()
    {
        _host.Remove(this);
        _unacknowledged.Clear();
        _unsent.Clear();
        _receive.DiscardOutOfOrder();
    }
}
