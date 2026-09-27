using System.Net;

namespace TCP.L4.Transport.Udp;

/// <summary>A datagram delivered to a <see cref="UdpSocket"/>.</summary>
/// <param name="RemoteAddress">The sender's address.</param>
/// <param name="RemotePort">The sender's port; zero when it expects no reply.</param>
/// <param name="Payload">The application message, exactly as sent: UDP preserves message boundaries.</param>
/// <param name="Broadcast">It was addressed to a broadcast or multicast address rather than to us alone.</param>
public readonly record struct UdpReceivedDatagram(IPAddress RemoteAddress, ushort RemotePort, ReadOnlyMemory<byte> Payload, bool Broadcast);

/// <summary>An ICMP error about a datagram this socket sent, such as "port unreachable" (RFC 1122 4.1.3.3).</summary>
/// <param name="RemoteAddress">Where the failed datagram was going.</param>
/// <param name="RemotePort">Its destination port.</param>
/// <param name="IcmpType">The ICMP message type, for example 3 (destination unreachable).</param>
/// <param name="IcmpCode">The ICMP code, for example 3 (port unreachable).</param>
public readonly record struct UdpError(IPAddress RemoteAddress, ushort RemotePort, byte IcmpType, byte IcmpCode)
{
    /// <summary>A short description for diagnostics.</summary>
    public override string ToString() => string.Format(UdpMessages.NetworkErrorFormat, IcmpType, IcmpCode);
}

/// <summary>
/// One bound UDP port: sends datagrams and raises an event for each one that arrives. Created by
/// <see cref="UdpHost.Bind"/>. APIs and callbacks run on the IPv4 receive/timer thread.
/// </summary>
/// <remarks>
/// <para>
/// UDP has no connection, so a socket can exchange datagrams with any number of peers. <see cref="Connect"/> only
/// records a default destination and filters arrivals to that one peer, as a connected socket does in the BSD
/// API; nothing is sent to the peer.
/// </para>
/// <para>
/// Nothing is retransmitted or reordered: each <see cref="SendTo"/> is one datagram, delivered at most once,
/// possibly never. When the network reports failure with ICMP, <see cref="ErrorReceived"/> tells the application,
/// which RFC 1122 4.1.3.3 requires, since UDP itself cannot do anything about it.
/// </para>
/// </remarks>
public sealed class UdpSocket : IDisposable
{
    private readonly UdpHost _host;
    private bool _disposed;

    /// <summary>Only <see cref="UdpHost.Bind"/> creates sockets, after reserving the port.</summary>
    internal UdpSocket(UdpHost host, ushort port)
    {
        _host = host;
        LocalPort = port;
    }

    /// <summary>The bound port.</summary>
    public ushort LocalPort { get; }

    /// <summary>Allow sending to broadcast and multicast addresses (the SO_BROADCAST safeguard against accidental floods).</summary>
    public bool EnableBroadcast { get; set; }

    /// <summary>The peer set by <see cref="Connect"/>, or null for an unconnected socket.</summary>
    public (IPAddress Address, ushort Port)? RemoteEndPoint { get; private set; }

    /// <summary>A datagram arrived for this port (from the connected peer only, once connected).</summary>
    public event Action<UdpSocket, UdpReceivedDatagram>? Received;

    /// <summary>The network reported that a datagram we sent could not be delivered.</summary>
    public event Action<UdpSocket, UdpError>? ErrorReceived;

    /// <summary>Sets the default destination and accepts datagrams only from it. Sends nothing.</summary>
    /// <exception cref="ArgumentException">The address or port is invalid.</exception>
    public void Connect(IPAddress remoteAddress, ushort remotePort)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _host.ValidateDestination(this, remoteAddress, remotePort);
        RemoteEndPoint = (remoteAddress, remotePort);
    }

    /// <summary>Sends one datagram to the connected peer.</summary>
    /// <returns>Whether the IP layer accepted it; true does not mean it arrived.</returns>
    /// <exception cref="InvalidOperationException">The socket is not connected.</exception>
    public bool Send(ReadOnlySpan<byte> payload)
    {
        if (RemoteEndPoint is not { } peer) throw new InvalidOperationException(UdpMessages.NotConnected);
        return SendTo(peer.Address, peer.Port, payload);
    }

    /// <summary>Sends one datagram. IPv4 fragments it if it exceeds the path MTU.</summary>
    /// <returns>Whether the IP layer accepted it (for example, a route existed); true does not mean it arrived.</returns>
    /// <exception cref="ArgumentException">The destination is invalid or the payload exceeds 65,507 bytes.</exception>
    /// <exception cref="InvalidOperationException">The destination is a broadcast address and <see cref="EnableBroadcast"/> is off.</exception>
    public bool SendTo(IPAddress remoteAddress, ushort remotePort, ReadOnlySpan<byte> payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _host.Send(this, remoteAddress, remotePort, payload);
    }

    /// <summary>Releases the port. Later datagrams to it earn "port unreachable".</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _host.Unbind(this);
    }

    /// <summary>Hands an arriving datagram to the application, unless a connected socket's peer did not send it.</summary>
    internal void Deliver(UdpReceivedDatagram datagram)
    {
        if (RemoteEndPoint is { } peer && (!peer.Address.Equals(datagram.RemoteAddress) || peer.Port != datagram.RemotePort)) return;
        Received?.Invoke(this, datagram);
    }

    /// <summary>Reports an ICMP error about one of our datagrams.</summary>
    internal void ReportError(UdpError error) => ErrorReceived?.Invoke(this, error);
}
