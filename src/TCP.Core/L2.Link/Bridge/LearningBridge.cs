using System.Buffers.Binary;
using TCP.L1.Physical;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Bridge;

/// <summary>A bounded VLAN-aware learning bridge with optional classic common spanning tree.</summary>
/// <remarks>
/// <para>
/// A bridge (a switch) joins several Ethernet segments into one network (IEEE 802.1D/802.1Q). For each frame it
/// learns which port the source MAC lives behind. It then forwards the frame only toward the port that leads to the
/// destination, or floods it to every other port when the destination is unknown, broadcast or multicast.
/// </para>
/// <para>
/// VLANs divide one bridge into separate broadcast domains. Access ports carry a single untagged VLAN (the PVID);
/// trunk ports carry several, identified by 802.1Q tags. Learning is per VLAN.
/// </para>
/// <para>
/// With redundant links a frame could circle forever. The optional <see cref="Bridge.SpanningTree"/> blocks ports
/// until the topology is loop-free. The bridge consults it for every frame and clears its table whenever the
/// topology changes.
/// </para>
/// </remarks>
public sealed class LearningBridge : IDisposable
{
    private const int MinimumFrameHeaderLength = EthernetConstants.HeaderLength;
    private const int MinimumBridgePortFrameLength = 64;
    private const int MaximumLearnedAddresses = 8192;
    private const int MaximumLinkLocalControlAddressSuffix = 15;
    private const ushort PriorityTaggedVlanIdentifier = 0;
    private const byte LinkLocalControlAddressFirstOctet = 0x01;
    private const byte LinkLocalControlAddressSecondOctet = 0x80;
    private const byte LinkLocalControlAddressThirdOctet = 0xC2;
    private const int ReceivePollIntervalMilliseconds = 10;
    private static readonly TimeSpan LearnedAddressLifetime = TimeSpan.FromMinutes(5);

    private readonly BridgePort[] _ports;
    private readonly TimeProvider _time;
    private readonly Dictionary<(ushort Vlan, MacAddress Mac), Entry> _table = [];

    /// <summary>Where a MAC address was last seen, and when.</summary>
    private readonly record struct Entry(int Port, DateTimeOffset Seen);

    /// <summary>How a frame was classified into a VLAN on ingress.</summary>
    /// <param name="Tagged">The frame arrived with an 802.1Q tag.</param>
    /// <param name="TagControlInformation">The tag's priority, drop eligibility and VLAN ID bits; 0 if untagged.</param>
    /// <param name="Identifier">The VLAN the frame belongs to, after substituting the PVID for untagged and priority-tagged frames.</param>
    private readonly record struct FrameVlan(bool Tagged, ushort TagControlInformation, ushort Identifier);

    /// <summary>Creates a bridge over the given ports.</summary>
    /// <param name="ports">At least two distinct ports with valid VLAN configurations.</param>
    /// <param name="timeProvider">Clock for address ageing and spanning tree timers; the system clock when null.</param>
    /// <param name="spanningTreeAddress">The bridge's own MAC address, which enables spanning tree; null disables it.</param>
    /// <exception cref="ArgumentException">Fewer than two ports, duplicate interfaces, or an invalid VLAN configuration.</exception>
    public LearningBridge(
        IEnumerable<BridgePort> ports,
        TimeProvider? timeProvider = null,
        MacAddress? spanningTreeAddress = null)
    {
        _ports = [.. ports];
        _time = timeProvider ?? TimeProvider.System;
        ValidatePorts(nameof(ports));
        if (spanningTreeAddress is { } bridgeMac) SpanningTree = CreateSpanningTree(bridgeMac);
    }

    /// <summary>The loop-prevention protocol instance, or null when spanning tree is disabled.</summary>
    public SpanningTree? SpanningTree { get; }

    /// <summary>Current time, for stamping and ageing learned addresses.</summary>
    private DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>
    /// Runs the bridge on the calling thread until cancelled: ticks spanning tree, then reads at most one frame from
    /// each port in turn, sleeping briefly when all ports are idle.
    /// </summary>
    public void Run(CancellationToken cancellationToken)
    {
        var buffer = new byte[IPacketInterface.MaximumFrameLength];
        while (!cancellationToken.IsCancellationRequested)
        {
            SpanningTree?.Tick();
            if (!ReceiveFromEachPort(buffer, cancellationToken)) cancellationToken.WaitHandle.WaitOne(ReceivePollIntervalMilliseconds);
        }
    }

    /// <summary>Bridges one frame that arrived on port <paramref name="ingress"/>: filter, classify, learn, then forward.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ingress"/> is not a port index.</exception>
    public void ProcessFrame(int ingress, ReadOnlySpan<byte> bytes)
    {
        if ((uint)ingress >= _ports.Length) throw new ArgumentOutOfRangeException(nameof(ingress));
        var input = _ports[ingress];
        if (bytes.Length < MinimumFrameHeaderLength || bytes.Length > input.MaximumFrameLength) return;

        var destination = ReadMac(bytes, EthernetConstants.DestinationAddressOffset);
        var source = ReadMac(bytes, EthernetConstants.SourceAddressOffset);
        if (source == default || source.IsMulticast) return;
        if (IsConsumedOrBlocked(ingress, bytes)) return;
        if (!TryClassifyVlan(input, bytes, out var vlan) || !HasBridgeableEncapsulation(input, bytes, vlan.Tagged)) return;

        Learn(vlan.Identifier, source, ingress);
        if (SpanningTree?.State(ingress) == BridgePortState.Learning) return;
        ForwardOrFlood(ingress, destination, bytes, vlan);
    }

    /// <summary>Disposes every port's interface.</summary>
    public void Dispose()
    {
        foreach (var port in _ports) port.Interface.Dispose();
    }

    /// <summary>
    /// Ports must be distinct, and each needs a VLAN configuration the bridge can honor: a PVID in 1..4094 that is
    /// among its VLANs, only valid VLAN IDs, a usable frame size, and exactly one VLAN on an access port.
    /// </summary>
    private void ValidatePorts(string parameterName)
    {
        if (_ports.Length < 2) throw new ArgumentException("A bridge needs at least two ports.", parameterName);
        if (_ports.Select(port => port.Interface.InterfaceName).Distinct().Count() != _ports.Length)
            throw new ArgumentException("Bridge ports must be distinct.", parameterName);
        if (!_ports.All(IsValidVlanConfiguration)) throw new ArgumentException("Invalid bridge VLAN configuration.", parameterName);
    }

    /// <summary>One port's VLAN settings are internally consistent; see <see cref="ValidatePorts"/>.</summary>
    private static bool IsValidVlanConfiguration(BridgePort port) =>
        IsUsableVlan(port.Pvid) &&
        port.Vlans.Contains(port.Pvid) &&
        port.Vlans.All(IsUsableVlan) &&
        port.MaximumFrameLength >= MinimumBridgePortFrameLength &&
        (port.Trunk || port.Vlans.Count == 1);

    /// <summary>VLAN 0 means "priority tag only" and 4095 is reserved, so real VLANs are 1..4094.</summary>
    private static bool IsUsableVlan(ushort vlan) =>
        vlan is not PriorityTaggedVlanIdentifier and <= EthernetConstants.MaximumVlanIdentifier;

    /// <summary>Spanning tree sends its BPDUs out of specific ports and flushes learned addresses on topology changes.</summary>
    private SpanningTree CreateSpanningTree(MacAddress bridgeMac)
    {
        var spanningTree = new SpanningTree(
            bridgeMac,
            [.. _ports.Select(port => port.HardwareAddress)],
            (port, frame) => _ports[port].Interface.Send(frame),
            _time);
        spanningTree.TopologyChanged += () => _table.Clear();
        return spanningTree;
    }

    /// <summary>One read per port per pass prevents a busy port starving another.</summary>
    /// <returns>Whether any port had a frame.</returns>
    private bool ReceiveFromEachPort(byte[] buffer, CancellationToken cancellationToken)
    {
        var received = false;
        for (var port = 0; port < _ports.Length && !cancellationToken.IsCancellationRequested; port++)
        {
            var length = _ports[port].Interface.Receive(buffer);
            if (length == 0) continue;
            received = true;
            ProcessFrame(port, buffer.AsSpan(0, length));
        }
        return received;
    }

    /// <summary>
    /// The frame goes no further when it is a spanning tree BPDU (consumed by the tree), when its ingress port is
    /// not yet learning, or when it is addressed to a reserved 802.1D link-local group, which bridges never forward.
    /// </summary>
    private bool IsConsumedOrBlocked(int ingress, ReadOnlySpan<byte> bytes) =>
        SpanningTree?.Receive(ingress, bytes) == true ||
        SpanningTree?.State(ingress) is BridgePortState.Blocking or BridgePortState.Listening ||
        IsReservedBridgeControlAddress(bytes);

    /// <summary>
    /// Assigns the frame to a VLAN (802.1Q ingress rules). Untagged and priority-tagged frames get the port's PVID.
    /// An access port accepts only its own VLAN. The port must be a member of the resulting VLAN.
    /// </summary>
    /// <returns>False when the frame must be dropped.</returns>
    private static bool TryClassifyVlan(BridgePort input, ReadOnlySpan<byte> bytes, out FrameVlan vlan)
    {
        vlan = default;
        var tagged = ReadUInt16(bytes, EthernetConstants.EtherTypeOrLengthOffset) == (ushort)EtherType.VlanTag;
        if (tagged && bytes.Length < EthernetConstants.VlanHeaderLength) return false;

        var tagControlInformation = tagged ? ReadUInt16(bytes, EthernetConstants.VlanControlInformationOffset) : (ushort)0;
        var identifier = (ushort)(tagControlInformation & EthernetConstants.VlanIdentifierMask);
        if (identifier == EthernetConstants.ReservedVlanIdentifier) return false;
        if (!input.Trunk && identifier != PriorityTaggedVlanIdentifier && identifier != input.Pvid) return false;
        if (identifier == PriorityTaggedVlanIdentifier) identifier = input.Pvid;
        if (!input.Vlans.Contains(identifier)) return false;

        vlan = new FrameVlan(tagged, tagControlInformation, identifier);
        return true;
    }

    /// <summary>
    /// This profile is a single customer VLAN bridge, not a provider (Q-in-Q) bridge. It rejects stacked tags,
    /// reserved type/length values, 802.3 lengths longer than the frame, and untagged frames that would exceed the
    /// port's size limit once tagged.
    /// </summary>
    private static bool HasBridgeableEncapsulation(BridgePort input, ReadOnlySpan<byte> bytes, bool tagged)
    {
        var typeOffset = tagged ? EthernetConstants.InnerEtherTypeOffset : EthernetConstants.EtherTypeOrLengthOffset;
        var innerTypeOrLength = ReadUInt16(bytes, typeOffset);
        if (innerTypeOrLength is (ushort)EtherType.VlanTag or (ushort)EtherType.ProviderVlanTag) return false;
        if (innerTypeOrLength is > EthernetConstants.Maximum8023Length and < EthernetConstants.MinimumEtherTypeValue) return false;

        var maximumIngressLength = input.MaximumFrameLength - (tagged ? 0 : EthernetConstants.VlanTagLength);
        if (bytes.Length > maximumIngressLength) return false;

        var payloadOffset = tagged ? EthernetConstants.VlanHeaderLength : EthernetConstants.HeaderLength;
        return innerTypeOrLength > EthernetConstants.Maximum8023Length || bytes.Length - payloadOffset >= innerTypeOrLength;
    }

    /// <summary>Remembers that <paramref name="source"/> is reachable through <paramref name="ingress"/> on this VLAN.</summary>
    private void Learn(ushort vlan, MacAddress source, int ingress)
    {
        ExpireLearnedAddresses();
        var key = (vlan, source);
        if (_table.Count >= MaximumLearnedAddresses && !_table.ContainsKey(key)) EvictLeastRecentlySeen();
        _table[key] = new Entry(ingress, Now);
    }

    /// <summary>
    /// A known unicast destination is forwarded to its port alone, or dropped if it lives on the ingress segment.
    /// Unknown, broadcast and multicast destinations are flooded to every other port.
    /// </summary>
    private void ForwardOrFlood(int ingress, MacAddress destination, ReadOnlySpan<byte> bytes, FrameVlan vlan)
    {
        if (!destination.IsMulticast && _table.TryGetValue((vlan.Identifier, destination), out var known))
        {
            if (known.Port != ingress) Forward(known.Port, bytes, vlan);
            return;
        }
        for (var egress = 0; egress < _ports.Length; egress++)
        {
            if (egress != ingress) Forward(egress, bytes, vlan);
        }
    }

    /// <summary>
    /// Sends the frame out of one port if that port is forwarding and a member of the VLAN. The frame is re-tagged
    /// for a trunk or untagged for an access port, and padded to the Ethernet minimum.
    /// </summary>
    private void Forward(int egress, ReadOnlySpan<byte> bytes, FrameVlan vlan)
    {
        var port = _ports[egress];
        if (SpanningTree is not null && SpanningTree.State(egress) != BridgePortState.Forwarding) return;
        if (!port.Vlans.Contains(vlan.Identifier)) return;

        var addedTagLength = port.Trunk ? EthernetConstants.VlanTagLength : 0;
        var removedTagLength = vlan.Tagged ? EthernetConstants.VlanTagLength : 0;
        var outputLength = Math.Max(EthernetConstants.MinimumFrameLengthWithoutFcs, bytes.Length + addedTagLength - removedTagLength);
        if (outputLength > port.MaximumFrameLength) return;
        port.Interface.Send(Retag(bytes, vlan, port.Trunk, outputLength));
    }

    /// <summary>
    /// Copies the addresses, then writes an 802.1Q tag when leaving through a trunk, keeping the frame's priority and
    /// drop eligibility. Then copies everything after the original tag or type field.
    /// </summary>
    private static byte[] Retag(ReadOnlySpan<byte> bytes, FrameVlan vlan, bool trunk, int outputLength)
    {
        var output = new byte[outputLength];
        bytes[..EthernetConstants.EtherTypeOrLengthOffset].CopyTo(output);
        var outputPayloadOffset = EthernetConstants.EtherTypeOrLengthOffset;
        if (trunk)
        {
            var priorityAndDropEligibility = vlan.TagControlInformation &
                (EthernetConstants.PriorityCodePointMask | EthernetConstants.DropEligibleIndicatorMask);
            WriteUInt16(output, EthernetConstants.EtherTypeOrLengthOffset, (ushort)EtherType.VlanTag);
            WriteUInt16(output, EthernetConstants.VlanControlInformationOffset, (ushort)(priorityAndDropEligibility | vlan.Identifier));
            outputPayloadOffset += EthernetConstants.VlanTagLength;
        }
        var inputPayloadOffset = vlan.Tagged ? EthernetConstants.InnerEtherTypeOffset : EthernetConstants.EtherTypeOrLengthOffset;
        bytes[inputPayloadOffset..].CopyTo(output.AsSpan(outputPayloadOffset));
        return output;
    }

    /// <summary>01-80-C2-00-00-00 through -0F: link-local groups (such as BPDUs and pause frames) that bridges must not forward.</summary>
    private static bool IsReservedBridgeControlAddress(ReadOnlySpan<byte> frame) =>
        frame[0] == LinkLocalControlAddressFirstOctet &&
        frame[1] == LinkLocalControlAddressSecondOctet &&
        frame[2] == LinkLocalControlAddressThirdOctet &&
        frame[3] == 0 &&
        frame[4] == 0 &&
        frame[5] <= MaximumLinkLocalControlAddressSuffix;

    /// <summary>Forgets addresses not heard from within the ageing time, so moved stations are relearned.</summary>
    private void ExpireLearnedAddresses()
    {
        var cutoff = Now - LearnedAddressLifetime;
        foreach (var key in _table.Where(entry => entry.Value.Seen <= cutoff).Select(entry => entry.Key).ToArray()) _table.Remove(key);
    }

    /// <summary>Makes room in a full table by dropping the address heard from least recently.</summary>
    private void EvictLeastRecentlySeen() => _table.Remove(_table.MinBy(entry => entry.Value.Seen).Key);

    /// <summary>Reads the MAC address at <paramref name="offset"/> in the frame.</summary>
    private static MacAddress ReadMac(ReadOnlySpan<byte> bytes, int offset) =>
        MacAddress.FromBytes(bytes.Slice(offset, EthernetConstants.MacAddressLength));

    /// <summary>Reads a big-endian (network order) 16-bit field.</summary>
    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, sizeof(ushort)));

    /// <summary>Writes a big-endian (network order) 16-bit field.</summary>
    private static void WriteUInt16(byte[] bytes, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), value);
}
