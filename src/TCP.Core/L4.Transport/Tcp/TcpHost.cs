using System.Net;
using System.Security.Cryptography;
using TCP.L3.Network;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;
using TCP.L3.Network.Icmp;
using TCP.L4.Transport.Tcp.Authentication;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Handshake;
using TCP.L4.Transport.Tcp.Reliability;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// Single-threaded TCP endpoint over one <see cref="IPv4Host"/>. Registers for IP protocol 6 and runs its
/// timers from <see cref="IPv4Host.Ticked"/>; call application APIs on that same thread.
/// </summary>
/// <remarks>
/// <para>
/// This is the transport layer (L4) for one IP address, sitting between the network layer below
/// (<see cref="IPv4Host"/>) and applications above. It:
/// </para>
/// <list type="bullet">
/// <item>demultiplexes arriving segments to a <see cref="TcpConnection"/> by four-tuple, or to a <see cref="TcpListener"/> by port;</item>
/// <item>answers segments for nothing with RST;</item>
/// <item>owns port allocation, ISN generation and the timestamp clock;</item>
/// <item>answers SYNs statelessly with SYN cookies when a listener's backlog is full;</item>
/// <item>issues Fast Open cookies as a server and caches them as a client;</item>
/// <item>holds the authentication keys that TCP-AO and MD5 connections use;</item>
/// <item>carries ECN marks between IP and TCP;</item>
/// <item>routes ICMP errors to the connection that caused them;</item>
/// <item>fans the IP layer's tick out to every connection's timers.</item>
/// </list>
/// <para>The protocol logic itself lives in <see cref="TcpConnection"/>.</para>
/// </remarks>
public sealed class TcpHost : IDisposable
{
    public const int DefaultBacklog = 32;
    public const int MaximumBacklog = 128;
    /// <summary>Receive buffer, and so maximum window, of connections that do not ask for another size.</summary>
    public const int DefaultReceiveCapacity = 262_144;
    /// <summary>Largest receive buffer; windows beyond 64 KiB need window scaling, which peers without it cannot use.</summary>
    public const int MaximumReceiveCapacity = 16_777_216;
    public const int MaximumConnections = 256;
    private const int MinimumBacklog = 1;
    private const int MinimumReceiveCapacity = 1;
    private const ushort UnspecifiedPort = 0;
    private const ushort FirstEphemeralPort = 49152;
    private const int EphemeralPortCount = ushort.MaxValue - FirstEphemeralPort + 1;
    private const int MaximumQueuedPackets = 1024;
    private const int MinimumSendMss = 1;
    private const byte EcnMask = 0b11;
    private const byte CongestionExperienced = 0b11; // CE codepoint (RFC 3168 5).
    private const uint ReplacementIsnGap = 1 << 18; // New ISN beyond an old TIME-WAIT connection's SND.NXT (RFC 6191).

    private readonly IPv4Host _ip;
    private readonly InitialSequenceNumberGenerator _initialSequences;
    private readonly SynCookieGenerator _synCookies;
    private readonly FastOpenCookieGenerator _fastOpenServer = new();
    private readonly Dictionary<ConnectionKey, TcpConnection> _connections = [];
    private readonly Dictionary<ushort, TcpListener> _listeners = [];
    private readonly List<TcpAuthenticationKey> _authenticationKeys = [];
    private readonly Queue<IPv4Packet> _receiveQueue = [];
    private bool _dispatching;
    private bool _disposed;

    /// <summary>Attaches TCP to <paramref name="ip"/>: claims IP protocol 6 and subscribes to its ICMP errors and timer ticks.</summary>
    /// <param name="ip">The network layer to run over.</param>
    /// <param name="settings">Extension and timer policy for every connection; <see cref="TcpSettings.Default"/> when null.</param>
    /// <exception cref="ArgumentOutOfRangeException">A setting is out of range.</exception>
    public TcpHost(IPv4Host ip, TcpSettings? settings = null)
    {
        Settings = settings ?? TcpSettings.Default;
        Settings.Validate();
        _ip = ip;
        Time = ip.Time;
        _initialSequences = new InitialSequenceNumberGenerator(Time);
        _synCookies = new SynCookieGenerator(Time);
        ip.RegisterProtocol((byte)IPv4ProtocolNumber.Tcp, Receive);
        ip.IcmpErrorReceived += OnIcmpError;
        ip.Ticked += Tick;
    }

    /// <summary>The policy every connection starts from.</summary>
    public TcpSettings Settings { get; }

    /// <summary>A snapshot of every live connection, including half-open and TIME-WAIT ones.</summary>
    public IReadOnlyCollection<TcpConnection> Connections => [.. _connections.Values];

    /// <summary>The IP layer's clock; every connection timer reads it.</summary>
    internal TimeProvider Time { get; }

    /// <summary>Our IPv4 address: the local half of every four-tuple.</summary>
    internal IPAddress Address => _ip.LocalAddress;

    /// <summary>The MSS we advertise in our SYNs: the most we can receive, derived from our own interface MTU.</summary>
    internal ushort AdvertisedMss => (ushort)SendMss(Address);

    /// <summary>The shared millisecond timestamp clock; connections add their own offset (RFC 7323 5.4).</summary>
    internal uint TimestampClock => unchecked((uint)Time.GetUtcNow().ToUnixTimeMilliseconds());

    /// <summary>Fast Open cookies this host has learned from servers, for active opens with initial data.</summary>
    internal FastOpenCookieCache FastOpenCookies { get; } = new();

    /// <summary>Passive open: accepts connections on <paramref name="port"/> until the returned listener is disposed.</summary>
    /// <param name="port">Local port; must be non-zero and not used by another listener or connection.</param>
    /// <param name="accepted">
    /// Called with each connection once its handshake completes, or as soon as its SYN arrives when it carries Fast
    /// Open data (the connection is then still in SYN-RECEIVED but can already read and send).
    /// </param>
    /// <param name="backlog">Most handshakes allowed in progress at once; further SYNs get SYN cookies or are dropped.</param>
    /// <param name="receiveCapacity">Receive buffer, and so maximum window, for each accepted connection.</param>
    /// <exception cref="ArgumentOutOfRangeException">An argument is outside its allowed range.</exception>
    /// <exception cref="InvalidOperationException">The port is already in use.</exception>
    public TcpListener Listen(
        ushort port, Action<TcpConnection> accepted, int backlog = DefaultBacklog, int receiveCapacity = DefaultReceiveCapacity)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(accepted);
        if (port == UnspecifiedPort) throw new ArgumentOutOfRangeException(nameof(port));
        if (backlog is < MinimumBacklog or > MaximumBacklog) throw new ArgumentOutOfRangeException(nameof(backlog));
        if (!IsValidReceiveCapacity(receiveCapacity)) throw new ArgumentOutOfRangeException(nameof(receiveCapacity));
        if (IsPortInUse(port)) throw new InvalidOperationException(TcpMessages.PortInUse);
        var listener = new TcpListener(this, port, accepted, backlog, receiveCapacity);
        _listeners.Add(port, listener);
        return listener;
    }

    /// <summary>
    /// Active open: sends a SYN and returns the connection in SYN-SENT. Completion arrives later through
    /// <see cref="TcpConnection.Connected"/>, and failure through <see cref="TcpConnection.StateChanged"/> to Closed.
    /// </summary>
    /// <param name="remoteAddress">Unicast IPv4 address of the peer.</param>
    /// <param name="remotePort">The peer's port; must be non-zero.</param>
    /// <param name="localPort">Our port, or 0 to pick a free ephemeral port.</param>
    /// <param name="receiveCapacity">Receive buffer, and so maximum window, for this connection.</param>
    /// <param name="initialData">
    /// Data to send first. With a Fast Open cookie cached from an earlier connection to this server, it goes on the
    /// SYN (RFC 7413); otherwise the SYN asks for a cookie and the data follows the handshake as usual.
    /// </param>
    /// <exception cref="ArgumentException">The endpoint or capacity is invalid.</exception>
    /// <exception cref="InvalidOperationException">The connection limit is reached, no port is free, or the four-tuple is taken.</exception>
    public TcpConnection Connect(IPAddress remoteAddress, ushort remotePort, ushort localPort = UnspecifiedPort,
        int receiveCapacity = DefaultReceiveCapacity, ReadOnlySpan<byte> initialData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(remoteAddress);
        if (!_ip.IsUnicastPeer(remoteAddress) || remotePort == UnspecifiedPort || !IsValidReceiveCapacity(receiveCapacity))
            throw new ArgumentException(TcpMessages.InvalidEndpoint);
        if (_connections.Count >= MaximumConnections) throw new InvalidOperationException(TcpMessages.ConnectionLimitReached);
        if (localPort == UnspecifiedPort) localPort = AllocateEphemeralPort(remoteAddress, remotePort);
        var key = new ConnectionKey(localPort, remoteAddress, remotePort);
        if (IsEndpointInUse(key)) throw new InvalidOperationException(TcpMessages.EndpointInUse);
        var connection = CreateConnection(key, receiveCapacity, listener: null);
        connection.QueueInitialData(initialData);
        connection.Open();
        return connection;
    }

    /// <summary>
    /// Protects connections with a peer by TCP-AO (RFC 5925) or an MD5 signature (RFC 2385). Applies to connections
    /// opened or accepted afterwards; segments from the peer that are not correctly signed are dropped silently.
    /// </summary>
    /// <exception cref="ArgumentException">The key is empty, or duplicates another key's peer, ports and send identifier.</exception>
    public void AddAuthenticationKey(TcpAuthenticationKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.MasterKey is not { Length: > 0 }) throw new ArgumentException(TcpMessages.InvalidAuthenticationKey, nameof(key));
        if (_authenticationKeys.Any(k =>
                k.Peer.Equals(key.Peer) && k.LocalPort == key.LocalPort && k.RemotePort == key.RemotePort && k.SendId == key.SendId))
            throw new ArgumentException(TcpMessages.AuthenticationKeyConflict, nameof(key));
        _authenticationKeys.Add(key);
    }

    /// <summary>Stops using a key for new connections; existing connections keep theirs.</summary>
    public bool RemoveAuthenticationKey(TcpAuthenticationKey key) => _authenticationKeys.Remove(key);

    /// <summary>
    /// Shuts TCP down: aborts every connection (sending RST), drops all listeners, and detaches from the IP
    /// layer's events. Safe to call twice.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var connection in _connections.Values.ToArray()) connection.Abort();
        _listeners.Clear();
        _ip.IcmpErrorReceived -= OnIcmpError;
        _ip.Ticked -= Tick;
    }

    /// <summary>
    /// Largest TCP payload that fits the route MTU to <paramref name="peer"/> without IP fragmentation: the MTU minus
    /// 40 header bytes. Off-subnet peers use 576, the MTU every IPv4 host must accept. With no route it also falls
    /// back to 576. The connection lowers this further on ICMP "fragmentation needed".
    /// </summary>
    internal int SendMss(IPAddress peer)
    {
        var mtu = _ip.TryGetSendMtu(peer, out var known) ? known : IPv4Constants.MinimumReassemblyLength;
        return Math.Max(MinimumSendMss, mtu - TcpWireFormat.IPv4AndTcpHeaderLength);
    }

    /// <summary>The timestamp clock offset for one connection; see <see cref="InitialSequenceNumberGenerator.TimestampOffset"/>.</summary>
    internal uint TimestampOffset(ConnectionKey connection) => _initialSequences.TimestampOffset(Address, connection);

    /// <summary>The authentication keys that cover a connection with these endpoints, most specific first.</summary>
    internal IReadOnlyList<TcpAuthenticationKey> AuthenticationKeysFor(IPAddress peer, ushort localPort, ushort remotePort) =>
        [.. _authenticationKeys.Where(k => k.Matches(peer, localPort, remotePort))
            .OrderByDescending(k => (k.LocalPort is null ? 0 : 1) + (k.RemotePort is null ? 0 : 1))];

    /// <summary>Sends a segment built by <paramref name="connection"/> to its peer. This is a connection's only path to the wire.</summary>
    /// <param name="connection">The sending connection.</param>
    /// <param name="segment">The segment, already signed if the connection is authenticated.</param>
    /// <param name="ecnField">The IP ECN field: ECT(0) for ECN-capable data, otherwise zero.</param>
    /// <returns>Whether the IP layer accepted the packet (for example, a route existed).</returns>
    internal bool Send(TcpConnection connection, TcpSegment segment, byte ecnField = 0) =>
        Send(connection.RemoteAddress, segment, ecnField);

    /// <summary>Answers a segment that has no connection to receive it (RFC 9293 3.10.7.1). Never resets a reset.</summary>
    internal void Reset(IPAddress destination, TcpSegment incoming)
    {
        if (incoming.Has(TcpFlags.Rst)) return;
        Send(destination, ResetFor(incoming));
    }

    /// <summary>Forgets a connection that reached CLOSED, freeing its four-tuple for reuse.</summary>
    internal void Remove(TcpConnection connection)
    {
        var key = new ConnectionKey(connection.LocalPort, connection.RemoteAddress, connection.RemotePort);
        if (_connections.GetValueOrDefault(key) == connection) _connections.Remove(key);
    }

    /// <summary>
    /// Unbinds a listener (from <see cref="TcpListener.Dispose"/>) and aborts its unfinished handshakes, which no
    /// longer have anyone to accept them. Ignores a listener that is already replaced or removed.
    /// </summary>
    internal void Stop(TcpListener listener)
    {
        if (_listeners.GetValueOrDefault(listener.Port) != listener) return;
        _listeners.Remove(listener.Port);
        foreach (var connection in HalfOpenConnections(listener).ToArray()) connection.Abort();
    }

    /// <summary>A receive buffer must hold at least one byte, and no more than a scaled window can advertise.</summary>
    private static bool IsValidReceiveCapacity(int capacity) => capacity is >= MinimumReceiveCapacity and <= MaximumReceiveCapacity;

    /// <summary>A port can be listened on only if no listener or connection is using it.</summary>
    private bool IsPortInUse(ushort port) => _listeners.ContainsKey(port) || _connections.Keys.Any(k => k.LocalPort == port);

    /// <summary>
    /// An outgoing connection needs a four-tuple nobody else has, including connections lingering in TIME-WAIT,
    /// on a port no listener owns.
    /// </summary>
    private bool IsEndpointInUse(ConnectionKey key) => _listeners.ContainsKey(key.LocalPort) || _connections.ContainsKey(key);

    /// <summary>Picks a free port from a random starting point so ports do not reveal connection history (RFC 6056).</summary>
    private ushort AllocateEphemeralPort(IPAddress remoteAddress, ushort remotePort)
    {
        var start = RandomNumberGenerator.GetInt32(EphemeralPortCount);
        for (var i = 0; i < EphemeralPortCount; i++)
        {
            var candidate = (ushort)(FirstEphemeralPort + (start + i) % EphemeralPortCount);
            if (!IsEndpointInUse(new ConnectionKey(candidate, remoteAddress, remotePort))) return candidate;
        }
        throw new InvalidOperationException(TcpMessages.EphemeralPortsExhausted);
    }

    /// <summary>
    /// Creates and registers a connection. The caller then starts its handshake with <see cref="TcpConnection.Open"/>
    /// (active), <see cref="TcpConnection.AcceptSyn"/> (passive) or <see cref="TcpConnection.AcceptCookie"/>.
    /// </summary>
    /// <param name="key">The connection's four-tuple (minus our address); must not be registered yet.</param>
    /// <param name="receiveCapacity">Receive buffer size for the new connection.</param>
    /// <param name="listener">The listener that accepted it, or null for an active open.</param>
    /// <param name="initialSequence">A fixed ISN (a SYN cookie), or null to generate one.</param>
    /// <param name="sequenceFloor">An old connection's SND.NXT that a generated ISN must lie beyond (RFC 6191).</param>
    private TcpConnection CreateConnection(ConnectionKey key, int receiveCapacity, TcpListener? listener,
        uint? initialSequence = null, uint? sequenceFloor = null)
    {
        var sequence = initialSequence ?? _initialSequences.Next(Address, key);
        if (sequenceFloor is { } floor && (SequenceNumber)sequence <= floor) sequence = unchecked(floor + ReplacementIsnGap);
        var connection = new TcpConnection(this, key.LocalPort, key.RemoteAddress, key.RemotePort, sequence, receiveCapacity, listener);
        _connections.Add(key, connection);
        return connection;
    }

    /// <summary>The listener's connections still in SYN-RECEIVED: the backlog that SYN floods try to exhaust.</summary>
    private IEnumerable<TcpConnection> HalfOpenConnections(TcpListener listener) =>
        _connections.Values.Where(c => c.Listener == listener && c.State == TcpState.SynReceived);

    /// <summary>
    /// Entry point from the IP layer for every protocol-6 packet. Accepts only unicast traffic addressed to us
    /// (TCP is point-to-point), queues it with a bound against floods, and processes the queue.
    /// </summary>
    private void Receive(IPv4Packet packet)
    {
        if (_disposed || !packet.DestinationAddress.Equals(Address) || !_ip.IsUnicastPeer(packet.SourceAddress)) return;
        if (_receiveQueue.Count >= MaximumQueuedPackets) return;
        _receiveQueue.Enqueue(packet);
        DrainReceiveQueue();
    }

    /// <summary>
    /// Handles queued packets one at a time. A reply sent while dispatching may be delivered straight
    /// back into <see cref="Receive"/>; it waits in the queue instead of re-entering a connection.
    /// </summary>
    private void DrainReceiveQueue()
    {
        if (_dispatching) return;
        _dispatching = true;
        try
        {
            while (_receiveQueue.TryDequeue(out var packet)) Dispatch(packet);
        }
        finally { _dispatching = false; }
    }

    /// <summary>
    /// Demultiplexing (RFC 9293 3.10.7). An exact four-tuple match goes to its connection, unless it is a TIME-WAIT
    /// connection that a new SYN may replace. Otherwise a bare SYN goes to the port's listener, an ACK to a listener
    /// may complete a SYN-cookie handshake, a RST is dropped, and anything else is answered with RST ("no one here")
    /// unless the peer uses authentication. Corrupt segments are dropped silently.
    /// </summary>
    private void Dispatch(IPv4Packet packet)
    {
        if (_disposed || !TryParseSegment(packet, out var segment, out var options)) return;
        var congestionExperienced = (packet.TypeOfService & EcnMask) == CongestionExperienced;
        var key = new ConnectionKey(segment.DestinationPort, packet.SourceAddress, segment.SourcePort);
        _listeners.TryGetValue(segment.DestinationPort, out var listener);
        if (_connections.TryGetValue(key, out var connection))
        {
            if (listener is not null && IsPlainSyn(segment) && connection.AcceptsReplacementSyn(segment, options))
                OfferToListener(listener, key, segment, options, connection.ReplaceInTimeWait());
            else connection.Receive(segment, congestionExperienced);
            return;
        }
        if (segment.Has(TcpFlags.Rst)) return;
        if (listener is not null)
        {
            if (!segment.Has(TcpFlags.Ack))
            {
                OfferToListener(listener, key, segment, options, sequenceFloor: null);
                return;
            }
            if (TryCompleteCookieHandshake(listener, key, segment, options, congestionExperienced)) return;
        }
        // RFC 5925 7.7: with a key configured, an unsigned RST could be forged, so send none.
        if (AuthenticationKeysFor(packet.SourceAddress, segment.DestinationPort, segment.SourcePort).Count > 0) return;
        Reset(packet.SourceAddress, segment);
    }

    /// <summary>Decodes the packet's payload, turning the codec's validation exceptions into a simple failure.</summary>
    /// <returns>False for a malformed segment or one with a bad checksum, which must be discarded without reply.</returns>
    private static bool TryParseSegment(IPv4Packet packet, out TcpSegment segment, out TcpOptions options)
    {
        try
        {
            segment = TcpSegment.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span);
            options = segment.ReadOptions();
            return true;
        }
        catch (ArgumentException)
        {
            segment = default;
            options = TcpOptions.None;
            return false;
        }
    }

    /// <summary>A connection request: SYN without ACK, RST or FIN, the only segment that can open a connection on a listener.</summary>
    private static bool IsPlainSyn(TcpSegment segment) =>
        segment.Has(TcpFlags.Syn) && !segment.Has(TcpFlags.Ack | TcpFlags.Rst | TcpFlags.Fin);

    /// <summary>
    /// Starts a passive open for a plain SYN. An authenticated peer's SYN must verify first. When the host or the
    /// listener's backlog is full, the SYN gets a SYN cookie instead, or is dropped so the peer retries.
    /// </summary>
    private void OfferToListener(TcpListener listener, ConnectionKey key, TcpSegment segment, TcpOptions options, uint? sequenceFloor)
    {
        if (!IsPlainSyn(segment)) return;
        var keys = AuthenticationKeysFor(key.RemoteAddress, key.LocalPort, key.RemotePort);
        if (keys.Count > 0 && !IsAuthenticSyn(keys, key, segment, options)) return;
        if (_connections.Count >= MaximumConnections) return;
        if (HalfOpenConnections(listener).Count() >= listener.Backlog)
        {
            if (Settings.SynCookies && keys.Count == 0) SendCookieSynAck(listener, key, segment, options);
            return;
        }
        var fastOpen = EvaluateFastOpen(key.RemoteAddress, segment, options);
        CreateConnection(key, listener.ReceiveCapacity, listener, sequenceFloor: sequenceFloor).AcceptSyn(segment, options, fastOpen);
    }

    /// <summary>Checks a SYN's signature with the SYN traffic key, before any state is created for it.</summary>
    private bool IsAuthenticSyn(IReadOnlyList<TcpAuthenticationKey> keys, ConnectionKey key, TcpSegment segment, TcpOptions options)
    {
        var verifier = new SegmentAuthenticator(keys, Address, key.RemoteAddress, key.LocalPort, key.RemotePort);
        verifier.SetInitialSequences(0, segment.SequenceNumber);
        return verifier.Verify(segment, options, 0);
    }

    /// <summary>
    /// The server side of Fast Open (RFC 7413 4.2.1): a cookie request or a stale cookie earns a fresh cookie on the
    /// SYN-ACK; a valid cookie on a SYN with data lets that data be accepted at once.
    /// </summary>
    private FastOpenRequest EvaluateFastOpen(IPAddress client, TcpSegment syn, TcpOptions options)
    {
        if (!Settings.FastOpen || options.FastOpenCookie is not { } cookie) return default;
        if (cookie.Length > 0 && _fastOpenServer.IsValid(client, cookie)) return new FastOpenRequest(true, !syn.Payload.IsEmpty, null);
        return new FastOpenRequest(true, false, _fastOpenServer.Create(client));
    }

    /// <summary>
    /// Answers a SYN without keeping state (RFC 4987 3.6): the SYN-ACK's ISN is a cookie, and with timestamps the
    /// negotiated options ride in the low bits of TSval. Options that cannot be remembered are not offered.
    /// </summary>
    private void SendCookieSynAck(TcpListener listener, ConnectionKey key, TcpSegment syn, TcpOptions options)
    {
        var peerMss = options.MaximumSegmentSize ?? TcpWireFormat.DefaultIPv4Mss;
        var cookie = _synCookies.Create(Address, key, syn.SequenceNumber, peerMss, out _);
        var ecn = Settings.ExplicitCongestionNotification && syn.Has(TcpFlags.Ece) && syn.Has(TcpFlags.Cwr);
        var writer = new TcpOptionWriter();
        writer.TryAdd(TcpOptionWriter.MaximumSegmentSize(AdvertisedMss));
        if (Settings.Timestamps && options.Timestamp is { } timestamp)
        {
            var sack = Settings.SelectiveAcknowledgments && options.SackPermitted;
            var scale = Settings.WindowScaling ? options.WindowScale : null;
            var remembered = new SynCookieOptions(scale, sack, ecn);
            var value = SynCookieGenerator.EncodeTimestamp(unchecked(TimestampClock + TimestampOffset(key)), remembered);
            var echoed = new TcpTimestamp(value, timestamp.Value);
            writer.TryAdd(sack ? TcpOptionWriter.SackPermittedAndTimestamp(echoed) : TcpOptionWriter.Timestamp(echoed));
            if (scale is not null) writer.TryAdd(TcpOptionWriter.WindowScale((byte)TcpConnection.WindowScaleFor(listener.ReceiveCapacity)));
        }
        else ecn = false; // Without timestamps the cookie cannot remember ECN.
        var flags = TcpFlags.Syn | TcpFlags.Ack | (ecn ? TcpFlags.Ece : TcpFlags.None);
        var window = (ushort)Math.Min(listener.ReceiveCapacity, TcpWireFormat.MaximumUnscaledWindow);
        var synAck = new TcpSegment(
            key.LocalPort, key.RemotePort, cookie, unchecked(syn.SequenceNumber + 1), flags, window, default, writer.ToArray());
        Send(key.RemoteAddress, synAck);
    }

    /// <summary>
    /// An ACK to a listening port may be the last step of a SYN-cookie handshake: if its acknowledgment number minus
    /// one is a cookie we issued for this four-tuple, create the connection from what the cookie recorded.
    /// </summary>
    private bool TryCompleteCookieHandshake(
        TcpListener listener, ConnectionKey key, TcpSegment segment, TcpOptions options, bool congestionExperienced)
    {
        if (!Settings.SynCookies || segment.Has(TcpFlags.Syn | TcpFlags.Rst) || _connections.Count >= MaximumConnections) return false;
        var peerSequence = unchecked(segment.SequenceNumber - 1);
        var ourSequence = unchecked(segment.AcknowledgmentNumber - 1);
        if (!_synCookies.TryValidate(Address, key, peerSequence, ourSequence, options.Timestamp?.EchoReply, out var cookie)) return false;
        var connection = CreateConnection(key, listener.ReceiveCapacity, listener, initialSequence: ourSequence);
        connection.AcceptCookie(segment, options, cookie, congestionExperienced);
        return true;
    }

    /// <summary>
    /// A reset the sender will accept: if the segment carried an ACK, the reset takes that sequence number;
    /// otherwise it acknowledges everything the segment occupied.
    /// </summary>
    private static TcpSegment ResetFor(TcpSegment incoming) => incoming.Has(TcpFlags.Ack)
        ? new TcpSegment(incoming.DestinationPort, incoming.SourcePort,
            incoming.AcknowledgmentNumber, TcpWireFormat.UnusedAcknowledgmentNumber,
            TcpFlags.Rst, TcpWireFormat.ResetWindow, default)
        : new TcpSegment(incoming.DestinationPort, incoming.SourcePort,
            TcpWireFormat.ResetSequenceNumber, unchecked(incoming.SequenceNumber + incoming.SequenceLength),
            TcpFlags.Rst | TcpFlags.Ack, TcpWireFormat.ResetWindow, default);

    /// <summary>
    /// Wraps a segment in an IPv4 packet and hands it down. Don't Fragment is set because TCP sizes segments
    /// to the path MTU itself, and routers report oversize packets back via ICMP (RFC 1191).
    /// </summary>
    /// <param name="destination">The peer.</param>
    /// <param name="segment">The segment to carry.</param>
    /// <param name="ecnField">The IP ECN field (the low two bits of the old Type of Service octet).</param>
    private bool Send(IPAddress destination, TcpSegment segment, byte ecnField = 0)
    {
        var payload = segment.Serialize(Address, destination);
        var packet = new IPv4Packet(ecnField, default, IPv4FragmentField.DontFragmentFlag, _ip.DefaultTimeToLive,
            (byte)IPv4ProtocolNumber.Tcp, Address, destination, default, payload);
        return _ip.SendIPv4(packet);
    }

    /// <summary>
    /// Routes an ICMP error (destination unreachable, fragmentation needed, ...) to the connection whose segment it
    /// quotes. That is how TCP learns about path MTU and unreachable peers from the network layer.
    /// </summary>
    private void OnIcmpError(IPv4Packet packet, IcmpPacket message)
    {
        // IPv4Host already validated the quotation and matched a recent send. Further bind
        // it to the TCP four-tuple and an outstanding sequence before changing transport state.
        if (!IcmpQuotedSegment.TryParse(message.Payload.Span, out var quoted)) return;
        if (_connections.TryGetValue(quoted.Connection, out var connection))
            connection.NetworkError(quoted.SequenceNumber, message, quoted.TotalLength);
    }

    /// <summary>
    /// The IP layer's periodic tick: gives every connection a chance to run its timers. Iterates a snapshot
    /// because a timer can close, and so remove, a connection.
    /// </summary>
    private void Tick()
    {
        foreach (var connection in _connections.Values.ToArray()) connection.Tick();
    }
}
