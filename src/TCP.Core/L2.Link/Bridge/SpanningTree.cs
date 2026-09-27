using System.Buffers.Binary;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Bridge;

/// <summary>Classic common spanning tree (802.1D BPDUs), driven by the bridge receive thread.</summary>
/// <remarks>
/// <para>
/// Redundant links between bridges create loops, and Ethernet frames have no TTL: a single broadcast would circle
/// and multiply until the network collapses. The Spanning Tree Protocol (IEEE 802.1D) prevents this. Bridges
/// exchange Configuration BPDUs, elect the bridge with the lowest identifier as root, and keep exactly one
/// loop-free path to it.
/// </para>
/// <para>
/// On each bridge, the port with the best path to the root becomes the root port, and on each segment the bridge
/// offering the best path becomes the designated bridge. All other ports block.
/// </para>
/// <para>
/// Ports move Blocking → Listening → Learning → Forwarding, spending one forward delay in each middle state, so
/// a new topology settles before frames flow. Topology Change Notifications travel up to the root, which then
/// tells every bridge to age out learned addresses quickly.
/// </para>
/// <para>
/// This implementation speaks only the classic version-0 BPDU; RSTP peers fall back to it. <see cref="LearningBridge"/>
/// feeds it every frame and asks it each port's <see cref="State"/>.
/// </para>
/// </remarks>
public sealed class SpanningTree
{
    /// <summary>BPDU timers are carried in units of 1/256 second.</summary>
    private const int TimerUnitsPerSecond = 256;
    private const ushort DefaultMaxAge = 20 * TimerUnitsPerSecond;
    private const ushort DefaultHelloTime = 2 * TimerUnitsPerSecond;
    private const ushort DefaultForwardDelay = 15 * TimerUnitsPerSecond;
    private const ushort MinimumMaxAge = 6 * TimerUnitsPerSecond;
    private const ushort MaximumMaxAge = 40 * TimerUnitsPerSecond;
    private const ushort MinimumHelloTime = TimerUnitsPerSecond;
    private const ushort MaximumHelloTime = 10 * TimerUnitsPerSecond;
    private const ushort MinimumForwardDelay = 4 * TimerUnitsPerSecond;
    private const ushort MaximumForwardDelay = 30 * TimerUnitsPerSecond;
    private const byte ConfigurationBpduType = 0;
    private const byte TopologyChangeNotificationBpduType = 0x80;
    private const byte TopologyChangeFlag = 0x01;
    private const byte TopologyChangeAcknowledgmentFlag = 0x80;
    private const ushort PortIdentifierPriority = 0x8000;
    private const uint PortPathCost = 20_000;
    private const ushort DefaultBridgePriority = 32_768;
    private const int MaximumPortIdentifier = 4095;
    /// <summary>The 802.1D bridge group address that BPDUs are sent to; bridges consume it and never forward it.</summary>
    private static ReadOnlySpan<byte> BridgeControlAddress => [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];
    /// <summary>LLC header for BPDUs: DSAP and SSAP 0x42 (spanning tree), control 0x03 (unnumbered information).</summary>
    private static ReadOnlySpan<byte> BpduLlcHeader => [0x42, 0x42, 0x03];
    private const int BpduLlcHeaderLength = 3;
    private const int MinimumBpduLength = 7;
    private const int ConfigurationBpduLength = 35;
    private const int ConfigurationBpduLengthWithLlc = BpduLlcHeaderLength + ConfigurationBpduLength;
    private const int TopologyChangeNotificationLengthWithLlc = 7;
    private const int MinimumBpduEthernetFrameLength = EthernetConstants.HeaderLength + BpduLlcHeaderLength + 4;
    private const int BpduDataOffset = EthernetConstants.HeaderLength + BpduLlcHeaderLength;
    private const int BpduProtocolIdentifierOffset = 0;
    private const int BpduVersionOffset = 2;
    private const int BpduTypeOffset = 3;
    private const int BpduFlagsOffset = 4;
    private const int BpduRootIdentifierOffset = 5;
    private const int BpduRootPathCostOffset = 13;
    private const int BpduBridgeIdentifierOffset = 17;
    private const int BpduPortIdentifierOffset = 25;
    private const int BpduMessageAgeOffset = 27;
    private const int BpduMaxAgeOffset = 29;
    private const int BpduHelloTimeOffset = 31;
    private const int BpduForwardDelayOffset = 33;
    private const int BpduTopologyChangeNotificationTypeOffset = BpduDataOffset + 3;
    private const int BpduProtocolIdentifierLength = sizeof(ushort);
    private const int BridgeIdentifierLength = sizeof(ulong);
    private const int BridgeIdentifierPriorityOffset = 0;
    private const int BridgeIdentifierMacOffset = sizeof(ushort);
    private static readonly TimeSpan ConfigurationTransmitInterval = TimeSpan.FromSeconds(1);

    private readonly TimeProvider _time;
    private readonly Action<int, byte[]> _send;
    private readonly MacAddress[] _macs;
    private readonly Port[] _ports;
    private readonly ulong _bridgeId;
    private ulong _root;
    private uint _cost;
    private int _rootPort = -1;
    private DateTimeOffset _nextHello;
    private DateTimeOffset _topologyUntil;
    private bool _notifyRoot;
    private ushort _maxAge = DefaultMaxAge;
    private ushort _hello = DefaultHelloTime;
    private ushort _delay = DefaultForwardDelay;

    /// <summary>Per-port protocol state.</summary>
    private sealed class Port(DateTimeOffset now)
    {
        public BridgePortState State = BridgePortState.Listening;
        /// <summary>When <see cref="State"/> last changed; forward-delay timing starts here.</summary>
        public DateTimeOffset Changed = now;
        /// <summary>The best Configuration BPDU heard on this port, or null if none is current.</summary>
        public Configuration? Received;
        /// <summary>When <see cref="Received"/> arrived, for ageing it.</summary>
        public DateTimeOffset Seen;
        /// <summary>This bridge is the designated bridge for the port's segment, so it sends BPDUs there.</summary>
        public bool Designated = true;
        /// <summary>A Topology Change Notification arrived here and must be acknowledged in the next BPDU.</summary>
        public bool Ack;
        /// <summary>The port's link is up.</summary>
        public bool Enabled = true;
        public DateTimeOffset LastSent = DateTimeOffset.MinValue;
    }

    /// <summary>The fields of a Configuration BPDU. Timers are in 1/256 second.</summary>
    private sealed record Configuration(byte Flags, ulong Root, uint Cost, ulong Bridge, ushort Port,
        ushort Age, ushort MaxAge, ushort Hello, ushort Delay);

    /// <summary>Creates the protocol for a bridge with the given ports, all starting in Listening.</summary>
    /// <param name="bridgeMac">The bridge's MAC address; with <paramref name="priority"/> it forms the bridge identifier.</param>
    /// <param name="portMacs">Each port's own MAC address, used as the source of its BPDUs.</param>
    /// <param name="send">Transmits a frame out of a port.</param>
    /// <param name="timeProvider">Clock for protocol timers; the system clock when null.</param>
    /// <param name="priority">Bridge priority; lower values are preferred as root.</param>
    /// <exception cref="ArgumentException">An address is not unicast, or the port count is out of range.</exception>
    public SpanningTree(
        MacAddress bridgeMac,
        IReadOnlyList<MacAddress> portMacs,
        Action<int, byte[]> send,
        TimeProvider? timeProvider = null,
        ushort priority = DefaultBridgePriority)
    {
        if (bridgeMac == default || bridgeMac.IsMulticast ||
            portMacs.Count is < 2 or > MaximumPortIdentifier ||
            portMacs.Any(mac => mac == default || mac.IsMulticast))
            throw new ArgumentException("STP requires unicast bridge and port MAC addresses.");
        _time = timeProvider ?? TimeProvider.System;
        _send = send;
        _macs = [.. portMacs];
        _root = _bridgeId = BridgeIdentifier(priority, bridgeMac);
        _ports = [.. portMacs.Select(_ => new Port(_time.GetUtcNow()))];
    }

    /// <summary>
    /// Raised when the active topology changes. The bridge flushes its learned addresses, because stations may now
    /// be reachable through different ports.
    /// </summary>
    public event Action? TopologyChanged;

    /// <summary>Identifier of the bridge currently believed to be root; our own until a better one is heard.</summary>
    public ulong RootId => _root;

    /// <summary>Index of the port leading toward the root, or -1 when this bridge is the root.</summary>
    public int RootPort => _rootPort;

    /// <summary>Current time, for ageing BPDUs and timing state transitions.</summary>
    private DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>The forwarding state of <paramref name="port"/>.</summary>
    public BridgePortState State(int port) => _ports[port].State;

    /// <summary>Reports a port's link going up or down. A downed port blocks, forgets its BPDU, and the tree is recomputed.</summary>
    public void SetLink(int port, bool up)
    {
        var state = _ports[port];
        if (state.Enabled == up) return;
        state.Enabled = up;
        state.Received = null;
        SetState(state, up ? BridgePortState.Listening : BridgePortState.Blocking);
        Recompute();
    }

    /// <summary>
    /// Runs the protocol timers: age out stale BPDUs, recompute roles, advance ports through Listening and Learning,
    /// and send hellos when due.
    /// </summary>
    public void Tick()
    {
        var now = Now;
        DiscardAgedInformation();
        Recompute();
        AdvancePortStates(now);
        if (now >= _nextHello) SendHello(now);
    }

    /// <summary>Consumes a spanning tree BPDU if the frame is one.</summary>
    /// <param name="port">Index of the port the frame arrived on.</param>
    /// <param name="frame">The whole Ethernet frame.</param>
    /// <returns>True when the frame was addressed to the bridge group (01-80-C2-00-00-00) and so must not be forwarded, even if invalid.</returns>
    public bool Receive(int port, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < EthernetConstants.HeaderLength ||
            !frame[..EthernetConstants.MacAddressLength].SequenceEqual(BridgeControlAddress))
            return false;
        if (!_ports[port].Enabled || frame.Length < MinimumBpduEthernetFrameLength || !TryReadBpdu(frame, out var bpdu)) return true;

        if (bpdu[BpduTypeOffset] == TopologyChangeNotificationBpduType)
        {
            ReceiveTopologyChangeNotification(_ports[port]);
            return true;
        }
        if (bpdu[BpduTypeOffset] == ConfigurationBpduType && bpdu.Length >= ConfigurationBpduLength &&
            ReadConfiguration(bpdu) is var configuration && IsValid(configuration))
            ReceiveConfiguration(port, configuration);
        return true;
    }

    /// <summary>
    /// Extracts the BPDU from an 802.3 frame: a sane length field, the 42-42-03 LLC header, protocol identifier 0,
    /// and version 0. Classic BPDUs only; RSTP peers fall back when they hear our version-0 BPDUs.
    /// </summary>
    private static bool TryReadBpdu(ReadOnlySpan<byte> frame, out ReadOnlySpan<byte> bpdu)
    {
        bpdu = default;
        var payloadLength = ReadUInt16(frame, EthernetConstants.EtherTypeOrLengthOffset);
        if (payloadLength > EthernetConstants.Maximum8023Length ||
            payloadLength < MinimumBpduLength ||
            frame.Length < EthernetConstants.HeaderLength + payloadLength ||
            !frame.Slice(EthernetConstants.HeaderLength, BpduLlcHeaderLength).SequenceEqual(BpduLlcHeader))
            return false;

        var candidate = frame.Slice(BpduDataOffset, payloadLength - BpduLlcHeaderLength);
        if (ReadUInt16(candidate, BpduProtocolIdentifierOffset) != 0 || candidate[BpduVersionOffset] != 0) return false;
        bpdu = candidate;
        return true;
    }

    /// <summary>
    /// A downstream bridge reports a topology change. If we are designated on that segment, acknowledge it and pass
    /// the news on toward the root.
    /// </summary>
    private void ReceiveTopologyChangeNotification(Port port)
    {
        if (!port.Designated) return;
        port.Ack = true;
        ChangedTopology();
        SendConfigurations();
    }

    /// <summary>Decodes the fields of a Configuration BPDU; <see cref="IsValid"/> judges them afterwards.</summary>
    private static Configuration ReadConfiguration(ReadOnlySpan<byte> bpdu) => new(
        Flags: bpdu[BpduFlagsOffset],
        Root: BinaryPrimitives.ReadUInt64BigEndian(bpdu[BpduRootIdentifierOffset..]),
        Cost: BinaryPrimitives.ReadUInt32BigEndian(bpdu[BpduRootPathCostOffset..]),
        Bridge: BinaryPrimitives.ReadUInt64BigEndian(bpdu[BpduBridgeIdentifierOffset..]),
        Port: ReadUInt16(bpdu, BpduPortIdentifierOffset),
        Age: ReadUInt16(bpdu, BpduMessageAgeOffset),
        MaxAge: ReadUInt16(bpdu, BpduMaxAgeOffset),
        Hello: ReadUInt16(bpdu, BpduHelloTimeOffset),
        Delay: ReadUInt16(bpdu, BpduForwardDelayOffset));

    /// <summary>
    /// Rejects stale messages, timers outside 802.1D's ranges or inconsistent with each other, a cost that would
    /// overflow when our path cost is added, and port identifier 0.
    /// </summary>
    private static bool IsValid(Configuration configuration) =>
        configuration.Age < configuration.MaxAge &&
        configuration.MaxAge is >= MinimumMaxAge and <= MaximumMaxAge &&
        configuration.Hello is >= MinimumHelloTime and <= MaximumHelloTime &&
        configuration.Delay is >= MinimumForwardDelay and <= MaximumForwardDelay &&
        configuration.Cost <= uint.MaxValue - PortPathCost &&
        configuration.Port != 0 &&
        configuration.MaxAge >= 2 * (configuration.Hello + MinimumHelloTime) &&
        configuration.MaxAge <= 2 * (configuration.Delay - MinimumHelloTime);

    /// <summary>
    /// Stores a Configuration BPDU if it is at least as good as the port's current one, or is a refresh from the same
    /// sender, then recomputes the tree. BPDUs from the root port also carry the topology-change flags. We then send
    /// our own BPDUs on the ports where we are designated.
    /// </summary>
    private void ReceiveConfiguration(int port, Configuration configuration)
    {
        var state = _ports[port];
        if (ShouldReplace(state.Received, configuration))
        {
            state.Received = configuration;
            state.Seen = Now;
            Recompute();
            if (port == _rootPort) ApplyRootTopologyFlags(configuration);
        }
        SendConfigurations();
    }

    /// <summary>
    /// Better or equal priority always wins. A worse message still replaces the old one when it comes from the same
    /// designated bridge and port, since that sender's information has genuinely changed.
    /// </summary>
    private static bool ShouldReplace(Configuration? previous, Configuration configuration) =>
        previous is null ||
        Vector(configuration).CompareTo(Vector(previous)) <= 0 ||
        (configuration.Bridge == previous.Bridge && configuration.Port == previous.Port);

    /// <summary>
    /// The root relays topology-change state in its BPDUs. An acknowledgment ends our notifications. While the TC
    /// flag is set, keep the change window open so addresses keep ageing fast.
    /// </summary>
    private void ApplyRootTopologyFlags(Configuration configuration)
    {
        if ((configuration.Flags & TopologyChangeAcknowledgmentFlag) != 0) _notifyRoot = false;
        if ((configuration.Flags & TopologyChangeFlag) == 0)
        {
            _topologyUntil = DateTimeOffset.MinValue;
            return;
        }
        if (_topologyUntil <= Now) TopologyChanged?.Invoke();
        _topologyUntil = Now + FromTimerUnits(configuration.MaxAge + configuration.Delay);
    }

    /// <summary>The fields that rank BPDUs, compared in order: lower is better.</summary>
    private static (ulong Root, uint Cost, ulong Bridge, ushort Port) Vector(Configuration configuration) =>
        (configuration.Root, configuration.Cost, configuration.Bridge, configuration.Port);

    /// <summary>A port identifier: default port priority in the high bits, 1-based port number in the low bits.</summary>
    private static ushort PortId(int port) => (ushort)(PortIdentifierPriority | (port + 1));

    /// <summary>The bridge identifier: 16-bit priority followed by the 48-bit MAC, compared as one 64-bit number.</summary>
    private static ulong BridgeIdentifier(ushort priority, MacAddress bridgeMac)
    {
        var identifier = new byte[BridgeIdentifierLength];
        BinaryPrimitives.WriteUInt16BigEndian(identifier.AsSpan(BridgeIdentifierPriorityOffset), priority);
        bridgeMac.WriteBytes(identifier.AsSpan(BridgeIdentifierMacOffset));
        return BinaryPrimitives.ReadUInt64BigEndian(identifier);
    }

    /// <summary>Current age of a port's stored BPDU in timer units: its message age plus time held here.</summary>
    private double Age(Port port) => port.Received!.Age + (Now - port.Seen).TotalSeconds * TimerUnitsPerSecond;

    /// <summary>Forgets BPDUs that have reached their max age: the bridge that sent them has gone silent.</summary>
    private void DiscardAgedInformation()
    {
        foreach (var port in _ports)
        {
            if (port.Received is { } received && Age(port) >= received.MaxAge) port.Received = null;
        }
    }

    /// <summary>
    /// The heart of 802.1D: elect the root and root port from the stored BPDUs, adopt the root's timers, and decide
    /// which ports are designated. Ports that are neither root nor designated block.
    /// </summary>
    private void Recompute()
    {
        var (best, rootPort) = ElectRootPort();
        var topologyChanged = _rootPort != rootPort || _root != best.Root;
        _rootPort = rootPort;
        _root = best.Root;
        _cost = best.Cost;
        AdoptTimers();
        AssignPortRoles();
        if (topologyChanged) ChangedTopology();
    }

    /// <summary>
    /// Picks the port whose BPDU offers the best path to the lowest root, comparing root, cost plus our path cost,
    /// sender bridge, sender port, then our port. If none beats ourselves as root, we are the root (port -1).
    /// </summary>
    private ((ulong Root, uint Cost, ulong Bridge, ushort Port, ushort ReceivingPort) Best, int RootPort) ElectRootPort()
    {
        (ulong Root, uint Cost, ulong Bridge, ushort Port, ushort ReceivingPort) best = (_bridgeId, 0u, _bridgeId, 0, 0);
        var rootPort = -1;
        for (var index = 0; index < _ports.Length; index++)
        {
            var port = _ports[index];
            if (!port.Enabled || port.Received is not { } received || Age(port) >= received.MaxAge) continue;
            var vector = (received.Root, received.Cost + PortPathCost, received.Bridge, received.Port, PortId(index));
            if (vector.CompareTo(best) >= 0) continue;
            best = vector;
            rootPort = index;
        }
        return (best, rootPort);
    }

    /// <summary>Every bridge uses the root's max age, hello time and forward delay; the root uses the defaults.</summary>
    private void AdoptTimers()
    {
        var source = _rootPort >= 0 ? _ports[_rootPort].Received! : null;
        _maxAge = source?.MaxAge ?? DefaultMaxAge;
        _hello = source?.Hello ?? DefaultHelloTime;
        _delay = source?.Delay ?? DefaultForwardDelay;
    }

    /// <summary>
    /// A port is designated when our BPDU would beat the one heard on it. Root and designated ports may forward, and
    /// start listening if they were blocked. All others block.
    /// </summary>
    private void AssignPortRoles()
    {
        for (var index = 0; index < _ports.Length; index++)
        {
            var port = _ports[index];
            port.Designated = port.Enabled &&
                (port.Received is not { } received || (_root, _cost, _bridgeId, PortId(index)).CompareTo(Vector(received)) < 0);
            var canForward = port.Enabled && (index == _rootPort || port.Designated);
            if (!canForward) SetState(port, BridgePortState.Blocking);
            else if (port.State == BridgePortState.Blocking) SetState(port, BridgePortState.Listening);
        }
    }

    /// <summary>After a forward delay in each, Listening becomes Learning and Learning becomes Forwarding.</summary>
    private void AdvancePortStates(DateTimeOffset now)
    {
        foreach (var port in _ports)
        {
            if (!port.Enabled || port.State is BridgePortState.Blocking or BridgePortState.Forwarding) continue;
            var elapsedTimerUnits = (now - port.Changed).TotalSeconds * TimerUnitsPerSecond;
            if (elapsedTimerUnits < _delay) continue;
            SetState(port, port.State == BridgePortState.Listening ? BridgePortState.Learning : BridgePortState.Forwarding);
        }
    }

    /// <summary>Every hello time: send Configuration BPDUs, and keep notifying the root of a pending topology change.</summary>
    private void SendHello(DateTimeOffset now)
    {
        _nextHello = now + FromTimerUnits(_hello);
        SendConfigurations();
        if (_notifyRoot && _rootPort >= 0) SendTopologyChangeNotification();
    }

    /// <summary>Entering or leaving Forwarding changes the active topology.</summary>
    private void SetState(Port port, BridgePortState state)
    {
        if (port.State == state) return;
        var affectsForwarding = port.State == BridgePortState.Forwarding || state == BridgePortState.Forwarding;
        port.State = state;
        port.Changed = Now;
        if (affectsForwarding) ChangedTopology();
    }

    /// <summary>
    /// Flushes addresses, then spreads the news. The root sets the TC flag in its BPDUs for max age plus forward
    /// delay; any other bridge notifies the root until acknowledged.
    /// </summary>
    private void ChangedTopology()
    {
        TopologyChanged?.Invoke();
        if (_rootPort >= 0)
        {
            _notifyRoot = true;
            return;
        }
        _notifyRoot = false;
        _topologyUntil = Now + FromTimerUnits(_maxAge + _delay);
    }

    /// <summary>
    /// Sends our Configuration BPDU on each designated port, at most once a second per port. Nothing is sent once the
    /// root's information has aged out.
    /// </summary>
    private void SendConfigurations()
    {
        var now = Now;
        for (var index = 0; index < _ports.Length; index++)
        {
            var port = _ports[index];
            if (!port.Enabled || !port.Designated || now - port.LastSent < ConfigurationTransmitInterval) continue;
            var messageAge = _rootPort < 0 ? 0 : Age(_ports[_rootPort]) + TimerUnitsPerSecond;
            if (messageAge >= _maxAge) continue;

            var flags = (byte)((now < _topologyUntil ? TopologyChangeFlag : 0) | (port.Ack ? TopologyChangeAcknowledgmentFlag : 0));
            var frame = ConfigurationFrame(index, flags, (ushort)messageAge);
            port.Ack = false;
            port.LastSent = now;
            _send(index, frame);
        }
    }

    /// <summary>Builds a Configuration BPDU advertising our root, cost, identity and timers from <paramref name="port"/>.</summary>
    private byte[] ConfigurationFrame(int port, byte flags, ushort messageAge)
    {
        var frame = Frame(port, ConfigurationBpduLengthWithLlc);
        var bpdu = frame.AsSpan(BpduDataOffset);
        bpdu[BpduFlagsOffset] = flags;
        BinaryPrimitives.WriteUInt64BigEndian(bpdu[BpduRootIdentifierOffset..], _root);
        BinaryPrimitives.WriteUInt32BigEndian(bpdu[BpduRootPathCostOffset..], _cost);
        BinaryPrimitives.WriteUInt64BigEndian(bpdu[BpduBridgeIdentifierOffset..], _bridgeId);
        BinaryPrimitives.WriteUInt16BigEndian(bpdu[BpduPortIdentifierOffset..], PortId(port));
        BinaryPrimitives.WriteUInt16BigEndian(bpdu[BpduMessageAgeOffset..], messageAge);
        BinaryPrimitives.WriteUInt16BigEndian(bpdu[BpduMaxAgeOffset..], _maxAge);
        BinaryPrimitives.WriteUInt16BigEndian(bpdu[BpduHelloTimeOffset..], _hello);
        BinaryPrimitives.WriteUInt16BigEndian(bpdu[BpduForwardDelayOffset..], _delay);
        return frame;
    }

    /// <summary>Tells the root, via the root port, that the topology changed.</summary>
    private void SendTopologyChangeNotification()
    {
        var frame = Frame(_rootPort, TopologyChangeNotificationLengthWithLlc);
        frame[BpduTopologyChangeNotificationTypeOffset] = TopologyChangeNotificationBpduType;
        _send(_rootPort, frame);
    }

    /// <summary>An 802.3 frame to the bridge group address from the port's MAC, with the BPDU LLC header and zeroed BPDU.</summary>
    private byte[] Frame(int port, int ieee8023PayloadLength)
    {
        var frame = new byte[EthernetConstants.MinimumFrameLengthWithoutFcs];
        BridgeControlAddress.CopyTo(frame.AsSpan(EthernetConstants.DestinationAddressOffset));
        _macs[port].WriteBytes(frame.AsSpan(EthernetConstants.SourceAddressOffset, EthernetConstants.MacAddressLength));
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(EthernetConstants.EtherTypeOrLengthOffset), (ushort)ieee8023PayloadLength);
        BpduLlcHeader.CopyTo(frame.AsSpan(EthernetConstants.HeaderLength));
        return frame;
    }

    /// <summary>Converts BPDU timer units (1/256 second) to a time span.</summary>
    private static TimeSpan FromTimerUnits(int timerUnits) => TimeSpan.FromSeconds(timerUnits / (double)TimerUnitsPerSecond);

    /// <summary>Reads a big-endian (network order) 16-bit field.</summary>
    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, sizeof(ushort)));
}
