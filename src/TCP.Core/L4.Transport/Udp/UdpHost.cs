using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TCP.L3.Network;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.Icmp;

namespace TCP.L4.Transport.Udp;

/// <summary>
/// UDP for one <see cref="IPv4Host"/>: registers for IP protocol 17, owns the port table, and delivers each arriving
/// datagram to the <see cref="UdpSocket"/> bound to its destination port. Single-threaded, like the rest of the stack.
/// </summary>
/// <remarks>
/// <para>This is the whole of UDP's transport work (RFC 768, RFC 1122 4.1):</para>
/// <list type="bullet">
/// <item>demultiplex by destination port, accepting unicast to us and broadcast or multicast;</item>
/// <item>verify the checksum and length, dropping bad datagrams silently;</item>
/// <item>answer a unicast datagram for an unbound port with ICMP "port unreachable" (RFC 1122 4.1.3.1);</item>
/// <item>pass ICMP errors about our own datagrams to the socket that sent them (RFC 1122 4.1.3.3);</item>
/// <item>allocate ephemeral ports from a random starting point (RFC 6056).</item>
/// </list>
/// <para>Unlike TCP it keeps no per-peer state and has no timers. IPv4 fragments datagrams larger than the MTU.</para>
/// </remarks>
public sealed class UdpHost : IDisposable
{
    private const ushort UnspecifiedPort = 0;
    private const ushort FirstEphemeralPort = 49152;
    private const int EphemeralPortCount = ushort.MaxValue - FirstEphemeralPort + 1;
    private const int QuotedUdpHeaderLength = UdpDatagram.HeaderLength;

    private readonly IPv4Host _ip;
    private readonly Dictionary<ushort, UdpSocket> _sockets = [];
    private bool _disposed;

    /// <summary>Attaches UDP to <paramref name="ip"/>: claims IP protocol 17 and subscribes to its ICMP errors.</summary>
    public UdpHost(IPv4Host ip)
    {
        _ip = ip;
        ip.RegisterProtocol((byte)IPv4ProtocolNumber.Udp, Receive);
        ip.IcmpErrorReceived += OnIcmpError;
    }

    /// <summary>A snapshot of the bound sockets.</summary>
    public IReadOnlyCollection<UdpSocket> Sockets => [.. _sockets.Values];

    /// <summary>Binds a port and returns its socket; dispose the socket to release the port.</summary>
    /// <param name="port">The local port, or 0 to pick a free ephemeral port (49152-65535).</param>
    /// <exception cref="InvalidOperationException">The port is already bound, or no ephemeral port is free.</exception>
    public UdpSocket Bind(ushort port = UnspecifiedPort)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (port == UnspecifiedPort) port = AllocateEphemeralPort();
        else if (_sockets.ContainsKey(port)) throw new InvalidOperationException(UdpMessages.PortInUse);
        var socket = new UdpSocket(this, port);
        _sockets.Add(port, socket);
        return socket;
    }

    /// <summary>Stops delivering to every socket and detaches from the IP layer's ICMP errors. Safe to call twice.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _sockets.Clear();
        _ip.IcmpErrorReceived -= OnIcmpError;
    }

    /// <summary>Checks a destination before sending or connecting: IPv4, a non-zero port, and broadcast only when enabled.</summary>
    internal void ValidateDestination(UdpSocket socket, IPAddress address, ushort port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork || port == UnspecifiedPort)
            throw new ArgumentException(UdpMessages.InvalidDestination);
        if (_ip.IsBroadcastOrMulticast(address) && !socket.EnableBroadcast)
            throw new InvalidOperationException(UdpMessages.BroadcastNotEnabled);
    }

    /// <summary>
    /// Wraps a payload in a UDP datagram and an IPv4 packet and hands it down. Don't Fragment is left clear, so IPv4
    /// fragments datagrams larger than the path MTU; UDP has no segmentation of its own.
    /// </summary>
    internal bool Send(UdpSocket socket, IPAddress destination, ushort port, ReadOnlySpan<byte> payload)
    {
        ValidateDestination(socket, destination, port);
        if (payload.Length > UdpDatagram.MaximumIPv4PayloadLength) throw new ArgumentException(UdpMessages.PayloadTooLarge);
        var datagram = new UdpDatagram(socket.LocalPort, port, payload.ToArray());
        var packet = new IPv4Packet(default, default, default, _ip.DefaultTimeToLive, (byte)IPv4ProtocolNumber.Udp,
            _ip.LocalAddress, destination, default, datagram.Serialize(_ip.LocalAddress, destination));
        return _ip.SendIPv4(packet);
    }

    /// <summary>Frees a socket's port, unless another socket has since taken it.</summary>
    internal void Unbind(UdpSocket socket)
    {
        if (_sockets.GetValueOrDefault(socket.LocalPort) == socket) _sockets.Remove(socket.LocalPort);
    }

    /// <summary>Picks a free port from a random starting point so ports do not reveal traffic history (RFC 6056).</summary>
    private ushort AllocateEphemeralPort()
    {
        var start = RandomNumberGenerator.GetInt32(EphemeralPortCount);
        for (var i = 0; i < EphemeralPortCount; i++)
        {
            var candidate = (ushort)(FirstEphemeralPort + (start + i) % EphemeralPortCount);
            if (!_sockets.ContainsKey(candidate)) return candidate;
        }
        throw new InvalidOperationException(UdpMessages.EphemeralPortsExhausted);
    }

    /// <summary>
    /// Entry point from the IP layer for every protocol-17 packet: accepts datagrams from valid unicast sources to
    /// our address, or to a broadcast or multicast address, and hands them to the bound socket.
    /// </summary>
    private void Receive(IPv4Packet packet)
    {
        if (_disposed || !_ip.IsUnicastPeer(packet.SourceAddress)) return;
        var broadcast = _ip.IsBroadcastOrMulticast(packet.DestinationAddress);
        if (!broadcast && !packet.DestinationAddress.Equals(_ip.LocalAddress)) return;
        if (!TryParse(packet, out var datagram)) return;
        if (_sockets.TryGetValue(datagram.DestinationPort, out var socket))
            socket.Deliver(new(packet.SourceAddress, datagram.SourcePort, datagram.Payload, broadcast));
        else if (!broadcast) _ip.ReportPortUnreachable(packet);
    }

    /// <summary>Decodes the payload, turning the codec's validation exceptions into a simple failure.</summary>
    /// <returns>False for a malformed datagram or one with a bad checksum, which must be discarded without reply.</returns>
    private static bool TryParse(IPv4Packet packet, out UdpDatagram datagram)
    {
        try
        {
            datagram = UdpDatagram.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span);
            return true;
        }
        catch (ArgumentException)
        {
            datagram = default;
            return false;
        }
    }

    /// <summary>
    /// Routes an ICMP error to the socket whose datagram it quotes. <see cref="IPv4Host"/> has already matched the
    /// quote to a datagram we sent recently (RFC 5927), so here only the protocol and ports are read.
    /// </summary>
    private void OnIcmpError(IPv4Packet packet, IcmpPacket message)
    {
        var quote = message.Payload.Span;
        if (quote.Length < IPv4Packet.MinimumHeaderLength || quote[IPv4Packet.ProtocolOffset] != (byte)IPv4ProtocolNumber.Udp) return;
        var headerLength =
            (quote[IPv4Packet.VersionAndHeaderLengthOffset] & IPv4Packet.HeaderLengthFieldMask) * IPv4Packet.HeaderLengthUnit;
        if (headerLength < IPv4Packet.MinimumHeaderLength || quote.Length < headerLength + QuotedUdpHeaderLength) return;
        var (sourcePort, destinationPort) = UdpDatagram.ReadPorts(quote[headerLength..]);
        if (!_sockets.TryGetValue(sourcePort, out var socket)) return;
        var destination = new IPAddress(quote.Slice(IPv4Packet.DestinationAddressOffset, IPv4Packet.IPv4AddressLength));
        socket.ReportError(new(destination, destinationPort, message.Type, message.Code));
    }
}
