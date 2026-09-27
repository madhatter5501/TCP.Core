using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;
using TCP.L3.Network.IPv4.Options;
using TCP.L3.Network.IPv4.Routing;
using TCP.L3.Network.Icmp;

namespace TCP.L3.Network;

/// <summary>
/// IPv4 host behavior for one interface address: local delivery, reassembly, options, ICMP echo and
/// errors, and the send path. Link-independent; the link beneath drives it from a single thread.
/// </summary>
/// <remarks>
/// <para>
/// This is the network layer (L3) of the stack. Below it, an <see cref="IIPv4Link"/> such as the Ethernet stack
/// carries datagrams to on-link neighbors. Above it, transport protocols such as TCP register with
/// <see cref="RegisterProtocol"/>.
/// </para>
/// <para>
/// Received datagrams (<see cref="Receive"/>) are filtered, reassembled, have their options processed, and are then
/// delivered to ICMP or to the registered protocol. Errors go back to the sender as ICMP messages. Sent datagrams
/// (<see cref="SendIPv4"/>) are validated, given an Identification, routed, and handed to the link. The link calls
/// <see cref="FragmentForTransmit"/> once it knows the next hop.
/// </para>
/// <para>
/// It is a host, not a router: it never forwards datagrams between interfaces (RFC 1122).
/// </para>
/// </remarks>
public sealed class IPv4Host
{
    private const ushort FieldsNotAllowedOnLocalSendMask =
        IPv4FragmentField.ReservedFlag | IPv4FragmentField.ReassemblyMask;
    private const int MinimumQuotedDatagramPayloadLength = 8;
    private const int MaximumDestinationUnreachableCode = 15;
    private const int MaximumTimeExceededCode = 1;
    private const int MaximumParameterProblemCode = 2;
    private const int MaximumRedirectCode = 3;
    private const int ParameterProblemPointerShift = 24;
    private const int FirstMulticastAddressOctet = 224;

    private readonly IIPv4Link _link;
    private readonly IPAddress _stackAddress;
    private readonly IPv4Subnet _subnet;
    private readonly TimeProvider _time;
    private readonly IPv4Reassembler _reassembler;
    private readonly Dictionary<byte, Action<IPv4Packet>> _protocols = [];
    private readonly IPv4IdentificationAllocator _identifications = new();
    private readonly RecentSendLog _recentSends = new();
    private readonly IcmpErrorRateLimiter _errorRateLimiter = new();
    private byte _defaultTtl = IPv4Constants.DefaultTimeToLive;

    /// <summary>Creates the host for one address on one link.</summary>
    /// <param name="link">The link layer that carries this host's datagrams.</param>
    /// <param name="address">This host's IPv4 address.</param>
    /// <param name="subnet">The directly connected subnet, which defines on-link neighbors and broadcast addresses.</param>
    /// <param name="timeProvider">Clock for timers; the system clock when null.</param>
    /// <param name="mtu">The link's MTU, used for the connected route.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="mtu"/> is outside 68..65535.</exception>
    public IPv4Host(
        IIPv4Link link,
        IPAddress address,
        IPv4Subnet subnet,
        TimeProvider? timeProvider = null,
        int mtu = IPv4Constants.DefaultMtu)
    {
        if (mtu is < IPv4Constants.MinimumMtu or > IPv4Packet.MaximumTotalLength) throw new ArgumentOutOfRangeException(nameof(mtu));
        _link = link;
        _stackAddress = address;
        _subnet = subnet;
        _time = timeProvider ?? TimeProvider.System;
        _reassembler = new IPv4Reassembler(_time);
        Routes = new IPv4RouteTable(subnet, mtu);
    }

    /// <summary>Whether datagrams carrying a source-route option are accepted. When false they are refused with ICMP.</summary>
    public bool AcceptSourceRoutes { get; set; } = true;

    /// <summary>Whether ICMP Redirects from our current gateway may change the route to a destination.</summary>
    public bool AcceptRedirects { get; set; } = true;

    /// <summary>This host's routing table: the connected subnet, configured routes and learned redirects.</summary>
    public IPv4RouteTable Routes { get; }

    /// <summary>This host's IPv4 address.</summary>
    public IPAddress LocalAddress => _stackAddress;

    /// <summary>The clock shared with the layers above.</summary>
    public TimeProvider Time => _time;

    /// <summary>TTL for datagrams this host originates. Must be non-zero.</summary>
    public byte DefaultTimeToLive
    {
        get => _defaultTtl;
        set => _defaultTtl = value != 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    /// <summary>
    /// Raised for a validated ICMP error (Destination Unreachable, Time Exceeded or Parameter Problem) about a
    /// datagram we recently sent. Arguments are the error datagram and message. Transport layers use it to
    /// learn about unreachable peers and path MTU.
    /// </summary>
    public event Action<IPv4Packet, IcmpPacket>? IcmpErrorReceived;

    /// <summary>Raised after an echo reply is handed to the link. Arguments are the request datagram and message.</summary>
    public event Action<IPv4Packet, IcmpPacket>? EchoRequestAnswered;

    /// <summary>Raised at the start of each <see cref="Tick"/> so upper layers can run their timers.</summary>
    public event Action? Ticked;

    /// <summary>Current time from the host's clock; fake in tests.</summary>
    private DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>Register a transport protocol. The handler receives a complete datagram, including options.</summary>
    /// <exception cref="ArgumentException">ICMP was requested; the host handles it.</exception>
    public void RegisterProtocol(byte protocol, Action<IPv4Packet> handler)
    {
        if (protocol == (byte)IPv4ProtocolNumber.Icmp) throw new ArgumentException("ICMP is handled by the host.", nameof(protocol));
        _protocols[protocol] = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    /// <summary>Run upper-layer timers and expire reassembly state. Call periodically while the link is ready.</summary>
    public void Tick()
    {
        Ticked?.Invoke();
        foreach (var expired in _reassembler.Expire())
        {
            SendError(expired.FirstFragment, expired.LinkBroadcast,
                IcmpMessageType.TimeExceeded, (byte)IcmpTimeExceededCode.FragmentReassemblyTimeExceeded);
        }
    }

    /// <summary>Process a datagram received from the link.</summary>
    /// <param name="datagram">The IPv4 datagram bytes, without link framing.</param>
    /// <param name="linkBroadcast">The link-layer destination was broadcast or multicast.</param>
    public void Receive(ReadOnlySpan<byte> datagram, bool linkBroadcast)
    {
        if (!TryParse(datagram, out var packet) || !IsAcceptableArrival(packet)) return;
        var broadcast = linkBroadcast || _subnet.IsBroadcast(packet.DestinationAddress);
        // Do not infer ARP mappings from arbitrary IP traffic.
        if (!_reassembler.TryAccept(packet, broadcast, out var complete, out broadcast, out var firstFragment)) return;
        Deliver(complete, broadcast, firstFragment);
    }

    /// <summary>Send a locally originated datagram. Returns false when no route exists or DF prevents sending.</summary>
    /// <param name="packet">A complete, unfragmented datagram whose source is this host.</param>
    /// <exception cref="ArgumentException">The datagram is not a valid local datagram, or its options are invalid.</exception>
    public bool SendIPv4(IPv4Packet packet)
    {
        if (!_link.IsReady) return false;
        ValidateLocalDatagram(packet);
        if (!HasDontFragment(packet)) packet = packet with { Identification = _identifications.Allocate(Now) };
        if (packet.DestinationAddress.Equals(_stackAddress))
        {
            Deliver(packet, false);
            return true;
        }
        return _subnet.IsBroadcast(packet.DestinationAddress) ? TrySendBroadcast(packet) : TrySendUnicast(packet);
    }

    /// <summary>
    /// Fragment a datagram for its route's current MTU. The link calls this once the next hop
    /// is resolved, so a route that disappeared while resolution was pending yields nothing.
    /// </summary>
    public IEnumerable<IPv4Packet> FragmentForTransmit(IPv4Packet packet)
    {
        if (!TryGetSendMtu(packet.DestinationAddress, out var mtu)) return [];
        return IPv4Fragmenter.Fragment(packet, mtu);
    }

    /// <summary>Whether <paramref name="address"/> can be a unicast peer: an IPv4 address that is a valid source and not a broadcast.</summary>
    internal bool IsUnicastPeer(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork && _subnet.IsValidSource(address) && !_subnet.IsBroadcast(address);

    /// <summary>Whether <paramref name="address"/> is the subnet or limited broadcast address, or a multicast group.</summary>
    internal bool IsBroadcastOrMulticast(IPAddress address) =>
        _subnet.IsBroadcast(address) || address.GetAddressBytes()[0] >= FirstMulticastAddressOctet;

    /// <summary>
    /// Tells the sender that no application listens on the datagram's destination port (ICMP type 3 code 3). A
    /// transport calls this for a unicast datagram nobody wants (RFC 1122 4.1.3.1); the usual rules against errors
    /// about broadcasts, fragments and errors, and the rate limit, still apply.
    /// </summary>
    internal void ReportPortUnreachable(IPv4Packet packet) =>
        SendError(packet, false, IcmpMessageType.DestinationUnreachable, (byte)IcmpDestinationUnreachableCode.PortUnreachable);

    /// <summary>
    /// The largest datagram to send toward <paramref name="destination"/>: the route MTU, capped at 576 bytes
    /// beyond the connected subnet, since every IPv4 host must accept that size (RFC 1122 3.3.3).
    /// </summary>
    /// <returns>False when no route exists.</returns>
    internal bool TryGetSendMtu(IPAddress destination, out int mtu)
    {
        if (!Routes.TryLookup(destination, out _, out var routeMtu))
        {
            mtu = routeMtu;
            return false;
        }
        mtu = PathMtu(destination, routeMtu);
        return true;
    }

    /// <summary>Decodes a received datagram. Malformed datagrams are dropped silently; no ICMP error is owed for them.</summary>
    private static bool TryParse(ReadOnlySpan<byte> datagram, out IPv4Packet packet)
    {
        try
        {
            packet = IPv4Packet.Parse(datagram);
            return true;
        }
        catch (ArgumentException)
        {
            packet = default;
            return false;
        }
    }

    /// <summary>Addressed to us or our subnet broadcast, from a plausible source, with the reserved flag clear.</summary>
    private bool IsAcceptableArrival(IPv4Packet packet) =>
        (packet.DestinationAddress.Equals(_stackAddress) || _subnet.IsBroadcast(packet.DestinationAddress)) &&
        _subnet.IsValidSource(packet.SourceAddress) &&
        (packet.FlagsAndFragmentOffset & IPv4FragmentField.ReservedFlag) == 0;

    /// <summary>
    /// Processes options, enforces source-route policy, and hands the datagram to ICMP or its protocol. Problems
    /// are reported with ICMP errors that quote <paramref name="firstFragment"/>, the header the sender will recognize.
    /// </summary>
    /// <param name="original">The complete datagram before option processing.</param>
    /// <param name="broadcast">It arrived as a broadcast, so no ICMP error may be sent about it.</param>
    /// <param name="firstFragment">For a reassembled datagram, its first fragment.</param>
    private void Deliver(IPv4Packet original, bool broadcast, IPv4Packet? firstFragment = null)
    {
        var quoted = firstFragment ?? original;
        if (!IPv4Options.TryProcess(original, _stackAddress, Now, out var packet, out var errorPointer, out var hasSourceRoute))
        {
            SendError(quoted, broadcast, IcmpMessageType.ParameterProblem, 0, (uint)errorPointer << ParameterProblemPointerShift);
            return;
        }
        if (hasSourceRoute && (!AcceptSourceRoutes || IPv4Options.HasIncompleteSourceRoute(packet)))
        {
            SendError(quoted, broadcast, IcmpMessageType.DestinationUnreachable, (byte)IcmpDestinationUnreachableCode.SourceRouteFailed);
            return;
        }
        DeliverToProtocol(packet, original, quoted, broadcast);
    }

    /// <summary>ICMP is handled here; other protocols go to their registered handler, or earn "protocol unreachable".</summary>
    private void DeliverToProtocol(IPv4Packet packet, IPv4Packet original, IPv4Packet quoted, bool broadcast)
    {
        if (packet.Protocol == (byte)IPv4ProtocolNumber.Icmp) HandleIcmp(packet, original, broadcast);
        else if (_protocols.TryGetValue(packet.Protocol, out var handler)) handler(packet);
        else SendError(quoted, broadcast, IcmpMessageType.DestinationUnreachable, (byte)IcmpDestinationUnreachableCode.ProtocolUnreachable);
    }

    /// <summary>Answers echo requests and processes error messages. Other ICMP types, and corrupt messages, are ignored.</summary>
    private void HandleIcmp(IPv4Packet packet, IPv4Packet original, bool broadcast)
    {
        if (!TryParseIcmp(packet, out var message)) return;
        switch ((IcmpMessageType)message.Type)
        {
            case IcmpMessageType.EchoRequest:
                HandleEchoRequest(packet, message, broadcast);
                break;
            case IcmpMessageType.DestinationUnreachable:
            case IcmpMessageType.Redirect:
            case IcmpMessageType.TimeExceeded:
            case IcmpMessageType.ParameterProblem:
                HandleIcmpError(packet, original, message, broadcast);
                break;
        }
    }

    /// <summary>Decodes the ICMP message; a corrupt one (bad checksum or too short) is ignored.</summary>
    private static bool TryParseIcmp(IPv4Packet packet, out IcmpPacket message)
    {
        try
        {
            message = IcmpPacket.Parse(packet.Payload.Span);
            return true;
        }
        catch (ArgumentException)
        {
            message = default;
            return false;
        }
    }

    /// <summary>
    /// Replies to a ping with the same identifier, sequence and data. The reply retraces any source route the
    /// request took.
    /// </summary>
    private void HandleEchoRequest(IPv4Packet packet, IcmpPacket request, bool broadcast)
    {
        // RFC 1122 permits silently discarding broadcast echo requests.
        if (request.Code != IcmpPacket.EchoCode || broadcast) return;

        var reply = packet with
        {
            SourceAddress = _stackAddress,
            DestinationAddress = packet.SourceAddress,
            TimeToLive = DefaultTimeToLive,
            FlagsAndFragmentOffset = 0,
            Payload = (request with { Type = IcmpPacket.EchoReplyType }).Serialize()
        };
        reply = IPv4Options.ReverseSourceRoute(packet, reply);
        if (SendIPv4(reply)) EchoRequestAnswered?.Invoke(packet, request);
    }

    /// <summary>
    /// Accepts an ICMP error only if its quote shows a datagram we sent recently (RFC 5927). A Redirect then
    /// updates the route; other errors are passed up through <see cref="IcmpErrorReceived"/>.
    /// </summary>
    private void HandleIcmpError(IPv4Packet packet, IPv4Packet original, IcmpPacket message, bool broadcast)
    {
        if (!IcmpErrorQuote.TryParse(message.Payload.Span, out var quote) || !quote.Source.Equals(_stackAddress)) return;
        if (!_recentSends.Contains(quote.Destination, quote.Protocol, quote.Identification, Now)) return;

        if ((IcmpMessageType)message.Type == IcmpMessageType.Redirect)
        {
            ApplyRedirect(packet, message, quote.Destination, broadcast);
            return;
        }
        if (HasKnownErrorCode(message)) IcmpErrorReceived?.Invoke(original, message);
    }

    /// <summary>
    /// A router says a better first hop exists for <paramref name="destination"/> (RFC 1122 3.2.2.2). The route
    /// table accepts it only from our current gateway for that destination.
    /// </summary>
    private void ApplyRedirect(IPv4Packet packet, IcmpPacket message, IPAddress destination, bool broadcast)
    {
        if (!AcceptRedirects || message.Code > MaximumRedirectCode || broadcast) return;
        var newGateway = ReadGatewayAddress(message);
        if (!newGateway.Equals(_stackAddress)) Routes.ApplyRedirect(packet.SourceAddress, destination, newGateway);
    }

    /// <summary>A Redirect carries the new gateway's address in the ICMP header's second word.</summary>
    private static IPAddress ReadGatewayAddress(IcmpPacket message)
    {
        var gatewayBytes = new byte[IPv4Packet.IPv4AddressLength];
        BinaryPrimitives.WriteUInt32BigEndian(gatewayBytes, message.RestOfHeader);
        return new IPAddress(gatewayBytes);
    }

    /// <summary>Ignores error codes beyond those the RFCs define for each type.</summary>
    private static bool HasKnownErrorCode(IcmpPacket message) => (IcmpMessageType)message.Type switch
    {
        IcmpMessageType.DestinationUnreachable => message.Code <= MaximumDestinationUnreachableCode,
        IcmpMessageType.TimeExceeded => message.Code <= MaximumTimeExceededCode,
        IcmpMessageType.ParameterProblem => message.Code <= MaximumParameterProblemCode,
        _ => true
    };

    /// <summary>
    /// Reports a problem with <paramref name="original"/> to its sender, quoting its header and first 8 payload
    /// bytes. Suppressed when the rules forbid an error and when the rate limit is spent.
    /// </summary>
    private void SendError(IPv4Packet original, bool broadcast, IcmpMessageType type, byte code, uint restOfHeader = 0)
    {
        if (broadcast || !MayReportErrorAbout(original) || !_errorRateLimiter.TryAcquire(Now)) return;
        SendIPv4(ErrorDatagram(original, type, code, restOfHeader));
    }

    /// <summary>
    /// RFC 1122 3.2.2: never send an ICMP error about a datagram sent to a broadcast or multicast address, from
    /// an invalid source, a fragment other than the first, or another ICMP error. This prevents error storms.
    /// </summary>
    private bool MayReportErrorAbout(IPv4Packet original) =>
        _subnet.IsValidSource(original.SourceAddress) &&
        !_subnet.IsBroadcast(original.DestinationAddress) &&
        original.DestinationAddress.GetAddressBytes()[0] < FirstMulticastAddressOctet &&
        (original.FlagsAndFragmentOffset & IPv4FragmentField.FragmentOffsetMask) == 0 &&
        !IsIcmpErrorMessage(original);

    /// <summary>
    /// Whether the datagram carries an ICMP error, as opposed to a query such as echo. An empty ICMP payload
    /// counts as an error, erring on the side of silence.
    /// </summary>
    private static bool IsIcmpErrorMessage(IPv4Packet packet)
    {
        if (packet.Protocol != (byte)IPv4ProtocolNumber.Icmp) return false;
        if (packet.Payload.IsEmpty) return true;
        return (IcmpMessageType)packet.Payload.Span[0] is IcmpMessageType.DestinationUnreachable
            or IcmpMessageType.SourceQuench
            or IcmpMessageType.Redirect
            or IcmpMessageType.TimeExceeded
            or IcmpMessageType.ParameterProblem;
    }

    /// <summary>Wraps an ICMP error, quoting the original's header and first 8 payload bytes, in a datagram back to its sender.</summary>
    private IPv4Packet ErrorDatagram(IPv4Packet original, IcmpMessageType type, byte code, uint restOfHeader)
    {
        var originalBytes = original.Serialize();
        var quoteLength = Math.Min(originalBytes.Length, original.HeaderLength + MinimumQuotedDatagramPayloadLength);
        var message = new IcmpPacket((byte)type, code, restOfHeader, originalBytes.AsMemory(0, quoteLength));
        return new IPv4Packet(0, 0, 0, DefaultTimeToLive, (byte)IPv4ProtocolNumber.Icmp,
            _stackAddress, original.SourceAddress, ReadOnlyMemory<byte>.Empty, message.Serialize());
    }

    /// <summary>
    /// A local datagram must come from our address, have a TTL, fit the maximum size, not be a fragment, and
    /// carry valid options. Options are checked now, before the datagram waits in an ARP queue.
    /// </summary>
    private void ValidateLocalDatagram(IPv4Packet packet)
    {
        if (!packet.SourceAddress.Equals(_stackAddress) ||
            packet.TimeToLive == 0 ||
            packet.TotalLength > IPv4Packet.MaximumTotalLength ||
            (packet.FlagsAndFragmentOffset & FieldsNotAllowedOnLocalSendMask) != 0)
            throw new ArgumentException("Expected a complete local IPv4 datagram with a nonzero TTL.", nameof(packet));
        if (!IPv4Options.TryProcess(packet, _stackAddress, Now, out _, out _, out _))
            throw new ArgumentException("Invalid IPv4 options.", nameof(packet));
    }

    /// <summary>Broadcasts are never fragmented, so one larger than the connected route's MTU is dropped.</summary>
    private bool TrySendBroadcast(IPv4Packet packet)
    {
        if (!Routes.TryLookup(_stackAddress, out _, out var mtu) || packet.TotalLength > mtu) return false;
        _link.SendBroadcast(packet);
        return true;
    }

    /// <summary>
    /// Routes a unicast datagram to its next hop and hands it to the link. Fragmentation happens later, in
    /// <see cref="FragmentForTransmit"/>; here an oversized datagram is only refused if Don't Fragment is set.
    /// </summary>
    private bool TrySendUnicast(IPv4Packet packet)
    {
        var destination = packet.DestinationAddress;
        if (!_subnet.IsValidSource(destination) || !Routes.TryLookup(destination, out var nextHop, out var routeMtu)) return false;
        // Under a strict source route, the destination is the first listed hop and must be reached directly.
        if (IPv4Options.HasStrictSourceRoute(packet) && !nextHop.Equals(destination)) return false;
        if (packet.TotalLength > PathMtu(destination, routeMtu) && HasDontFragment(packet)) return false;

        _recentSends.Record(packet, Now);
        _link.SendToNeighbor(nextHop, packet);
        return true;
    }

    /// <summary>Off-subnet paths are assumed to carry only the 576-byte minimum, since their MTU is unknown.</summary>
    private int PathMtu(IPAddress destination, int routeMtu) =>
        _subnet.Contains(destination) ? routeMtu : Math.Min(routeMtu, IPv4Constants.MinimumReassemblyLength);

    /// <summary>The sender forbade fragmentation, typically because it is doing path MTU discovery.</summary>
    private static bool HasDontFragment(IPv4Packet packet) =>
        (packet.FlagsAndFragmentOffset & IPv4FragmentField.DontFragmentFlag) != 0;
}
