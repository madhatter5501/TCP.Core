using System.Net;
using System.Collections.Concurrent;
using TCP.L1.Physical;
using TCP.L2.Link.Arp;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Udp;

namespace TCP.Stack;

/// <summary>
/// Binds an <see cref="IPv4Host"/> to one untagged Ethernet interface: frame filtering, EtherType
/// dispatch, ARP, and address-conflict probing. Protocol processing and timers run on its receive thread.
/// </summary>
/// <remarks>
/// <para>
/// This assembles a complete host stack for one network card. From the bottom up:
/// </para>
/// <list type="number">
/// <item>The <see cref="IPacketInterface"/> (L1) moves raw frames.</item>
/// <item>This class plays L2: it filters frames addressed to us, answers and learns from ARP, and claims the address before use.</item>
/// <item><see cref="IPv4"/> (L3) handles datagrams, reaching the link through the <see cref="IIPv4Link"/> interface this class implements.</item>
/// <item><see cref="Tcp"/> and <see cref="Udp"/> (L4) run on top.</item>
/// </list>
/// <para>
/// Everything runs on the thread that calls <see cref="Run"/>. Other threads hand work over with <see cref="TrySchedule"/>.
/// </para>
/// </remarks>
public sealed class EthernetStack : IIPv4Link, IDisposable
{
    private const int ReceivePollIntervalMilliseconds = 10;
    private const int MaximumScheduledActions = 4096;
    private const int MaximumScheduledActionsPerTurn = 64;

    private readonly IPacketInterface _packetInterface;
    private readonly IPAddress _stackAddress;
    private readonly IPv4Subnet _subnet;
    private readonly MacAddress _hardwareAddress;
    private readonly TimeProvider _time;
    private readonly ArpCache _arpCache;
    private readonly ArpResolver _resolver;
    private readonly ConcurrentQueue<Action> _scheduledActions = new();
    private AddressClaim? _claim;
    private int _scheduledActionCount;

    /// <summary>
    /// Creates an IPv4 host over a caller-provided Ethernet frame interface.
    /// The stack owns and disposes <paramref name="port"/>.
    /// </summary>
    /// <param name="port">The Ethernet interface to send and receive frames on.</param>
    /// <param name="address">This host's IPv4 address.</param>
    /// <param name="mac">This host's MAC address.</param>
    /// <param name="subnet">The directly connected subnet.</param>
    /// <param name="timeProvider">Clock for every protocol timer; the system clock when null.</param>
    /// <param name="mtu">The link MTU.</param>
    public EthernetStack(
        IPacketInterface port,
        IPAddress address,
        MacAddress mac,
        IPv4Subnet subnet,
        TimeProvider? timeProvider = null,
        int mtu = IPv4Constants.DefaultMtu)
    {
        _time = timeProvider ?? TimeProvider.System;
        IPv4 = new IPv4Host(this, address, subnet, _time, mtu);
        Tcp = new TcpHost(IPv4);
        Udp = new UdpHost(IPv4);
        _packetInterface = port;
        _stackAddress = address;
        _hardwareAddress = mac;
        _subnet = subnet;
        _arpCache = new ArpCache(_time);
        _resolver = new ArpResolver(_arpCache, SendArpRequest, TransmitResolved, _time);
        _resolver.ResolutionFailed += OnResolutionFailed;
    }

    /// <summary>The network layer bound to this interface.</summary>
    public IPv4Host IPv4 { get; }

    /// <summary>The TCP layer over <see cref="IPv4"/>.</summary>
    public TcpHost Tcp { get; }

    /// <summary>The UDP layer over <see cref="IPv4"/>.</summary>
    public UdpHost Udp { get; }

    /// <summary>This interface's MAC address.</summary>
    public MacAddress HardwareAddress => _hardwareAddress;

    /// <summary>Whether the address claim has succeeded, so IP traffic may flow. True before <see cref="Run"/> starts a claim.</summary>
    public bool IsReady => _claim is not { Ready: false };

    /// <summary>ARP got no answer for a neighbor; datagrams to it were dropped and, if it is a gateway, routing avoids it for a while.</summary>
    public event Action<IPAddress>? NeighborResolutionFailed;

    /// <summary>Raised once the address-conflict probe completes and the stack begins serving.</summary>
    public event Action? AddressClaimed;

    /// <summary>
    /// Runs the stack on the calling thread until cancelled. It first claims the address (RFC 5227), then loops:
    /// run scheduled work, run timers, and process one received frame, sleeping briefly when the wire is quiet.
    /// </summary>
    public void Run(CancellationToken cancellationToken)
    {
        _claim = new AddressClaim(_stackAddress, _hardwareAddress, packet => SendArp(packet, MacAddress.Broadcast), _time);
        var buffer = new byte[IPacketInterface.MaximumFrameLength];
        var announced = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            RunScheduledActions();
            Tick();
            if (_claim.Ready && !announced)
            {
                AddressClaimed?.Invoke();
                announced = true;
            }
            var length = _packetInterface.Receive(buffer);
            if (length == 0)
            {
                cancellationToken.WaitHandle.WaitOne(ReceivePollIntervalMilliseconds);
                continue;
            }
            ProcessFrame(buffer.AsSpan(0, length));
        }
    }

    /// <summary>Schedules protocol operations to run on this stack's receive/timer thread.</summary>
    /// <returns>False when the queue is full; the caller should back off.</returns>
    public bool TrySchedule(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        while (true)
        {
            var count = Volatile.Read(ref _scheduledActionCount);
            if (count >= MaximumScheduledActions) return false;
            if (Interlocked.CompareExchange(ref _scheduledActionCount, count + 1, count) == count) break;
        }
        _scheduledActions.Enqueue(action);
        return true;
    }

    /// <summary>Stops TCP (aborting its connections) and UDP, then releases the interface.</summary>
    public void Dispose()
    {
        try
        {
            Tcp.Dispose();
            Udp.Dispose();
        }
        finally { _packetInterface.Dispose(); }
    }

    /// <summary>Looks up a neighbor's MAC address in the ARP cache without triggering resolution.</summary>
    internal bool TryResolveNeighbor(IPAddress address, out MacAddress mac) => _arpCache.TryResolve(address, out mac);

    /// <summary>Drives the address claim and, once the address is ours, ARP retries and the IP and TCP timers.</summary>
    internal void Tick()
    {
        _claim?.Tick();
        if (!IsReady) return;
        _resolver.Tick();
        IPv4.Tick();
    }

    /// <summary>
    /// Accepts one received frame. It must be untagged, come from a unicast station other than us, and be addressed
    /// to us or to broadcast. ARP is handled here; IPv4 goes up once the address is claimed. Other EtherTypes are ignored.
    /// </summary>
    internal void ProcessFrame(ReadOnlySpan<byte> bytes)
    {
        if (!TryParseFrame(bytes, out var frame) || !IsForThisHost(frame)) return;
        if (frame.EtherType == (ushort)EtherType.Arp) ProcessArp(frame);
        else if (frame.EtherType == (ushort)EtherType.IPv4 && IsReady) IPv4.Receive(frame.Payload.Span, frame.Destination.IsMulticast);
    }

    /// <summary>Runs up to a fixed number of queued actions per loop turn, so a busy producer cannot starve reception.</summary>
    private void RunScheduledActions()
    {
        for (var actionCount = 0;
             actionCount < MaximumScheduledActionsPerTurn && _scheduledActions.TryDequeue(out var action);
             actionCount++)
        {
            Interlocked.Decrement(ref _scheduledActionCount);
            action();
        }
    }

    /// <summary>Decodes a received frame; malformed frames are dropped silently.</summary>
    private static bool TryParseFrame(ReadOnlySpan<byte> bytes, out EthernetFrame frame)
    {
        try
        {
            frame = EthernetFrame.Parse(bytes);
            return true;
        }
        catch (ArgumentException)
        {
            frame = default;
            return false;
        }
    }

    /// <summary>
    /// The host stack attaches to an untagged interface, so only untagged or priority-tagged frames qualify. Our own
    /// echoed frames and frames with an invalid source are dropped, as are frames addressed to other stations.
    /// </summary>
    private bool IsForThisHost(EthernetFrame frame)
    {
        if (frame.VlanTag is { } vlanTag && (vlanTag & EthernetConstants.VlanIdentifierMask) != 0) return false;
        if (frame.Source == _hardwareAddress || frame.Source == default || frame.Source.IsMulticast) return false;
        return frame.Destination == _hardwareAddress || frame.Destination == MacAddress.Broadcast;
    }

    /// <summary>
    /// Feeds ARP to the address claim for conflict detection, then, once the address is ours, learns from the packet
    /// and answers requests for our address.
    /// </summary>
    private void ProcessArp(EthernetFrame frame)
    {
        if (!TryParseArp(frame, out var packet) || !IsConsistentArp(packet, frame)) return;
        _claim?.Observe(packet);
        if (!IsReady || !HasAcceptableSender(packet)) return;
        if (ShouldLearn(packet)) _resolver.Learned(packet.SenderProtocolAddress, packet.SenderHardwareAddress);
        if (ArpResponder.TryCreateReply(packet, _stackAddress, _hardwareAddress, out var reply))
            SendArp(reply, packet.SenderHardwareAddress);
    }

    /// <summary>Decodes an ARP payload; anything other than Ethernet/IPv4 ARP is ignored.</summary>
    private static bool TryParseArp(EthernetFrame frame, out ArpPacket packet)
    {
        try
        {
            packet = ArpPacket.Parse(frame.Payload.Span);
            return true;
        }
        catch (ArgumentException)
        {
            packet = default;
            return false;
        }
    }

    /// <summary>A known operation, with a sender hardware address that matches the frame's source, which blocks simple ARP spoofing.</summary>
    private static bool IsConsistentArp(ArpPacket packet, EthernetFrame frame) =>
        packet.Operation is ArpOperation.Request or ArpOperation.Reply && packet.SenderHardwareAddress == frame.Source;

    /// <summary>A sender address of 0.0.0.0 is only legitimate on a probe request; any other must be a valid source.</summary>
    private bool HasAcceptableSender(ArpPacket packet) =>
        packet.SenderProtocolAddress.Equals(IPAddress.Any)
            ? packet.Operation == ArpOperation.Request
            : _subnet.IsValidSource(packet.SenderProtocolAddress);

    /// <summary>
    /// RFC 826: update an existing mapping, or add a new one when we are the target. Only usable on-link neighbors
    /// other than ourselves qualify, so bystanders' chatter cannot fill the cache.
    /// </summary>
    private bool ShouldLearn(ArpPacket packet) =>
        !packet.SenderProtocolAddress.Equals(_stackAddress) &&
        _subnet.TryGetNextHop(packet.SenderProtocolAddress, out _) &&
        (packet.TargetProtocolAddress.Equals(_stackAddress) || _arpCache.TryResolve(packet.SenderProtocolAddress, out _));

    void IIPv4Link.SendBroadcast(IPv4Packet packet) => Transmit(MacAddress.Broadcast, packet);

    void IIPv4Link.SendToNeighbor(IPAddress nextHop, IPv4Packet packet) => _resolver.Send(nextHop, packet.Serialize());

    /// <summary>
    /// Once ARP has the neighbor's MAC, fragments the datagram for the route's current MTU and sends each piece.
    /// Fragmenting here rather than before resolution picks up any MTU change learned while waiting.
    /// </summary>
    private void TransmitResolved(MacAddress mac, byte[] bytes)
    {
        foreach (var fragment in IPv4.FragmentForTransmit(IPv4Packet.Parse(bytes))) Transmit(mac, fragment);
    }

    /// <summary>A neighbor that never answered ARP may be a dead gateway; tell routing, then the application.</summary>
    private void OnResolutionFailed(IPAddress target)
    {
        IPv4.Routes.MarkUnreachable(target);
        NeighborResolutionFailed?.Invoke(target);
    }

    /// <summary>Broadcasts "who has <paramref name="target"/>?" on behalf of the resolver.</summary>
    private void SendArpRequest(IPAddress target) =>
        SendArp(ArpPacket.CreateRequest(_hardwareAddress, _stackAddress, target), MacAddress.Broadcast);

    /// <summary>Frames an IPv4 datagram (EtherType 0x0800) to <paramref name="mac"/> and puts it on the wire.</summary>
    private void Transmit(MacAddress mac, IPv4Packet packet) =>
        _packetInterface.Send(new EthernetFrame(mac, _hardwareAddress, (ushort)EtherType.IPv4, packet.Serialize()).Serialize());

    /// <summary>Frames an ARP packet (EtherType 0x0806) to <paramref name="destination"/> and puts it on the wire.</summary>
    private void SendArp(ArpPacket packet, MacAddress destination) =>
        _packetInterface.Send(new EthernetFrame(destination, _hardwareAddress, (ushort)EtherType.Arp, packet.Serialize()).Serialize());
}
