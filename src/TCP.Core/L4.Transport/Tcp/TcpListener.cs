using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// A passive open: the LISTEN state of RFC 9293, bound to one local port. Created by
/// <see cref="TcpHost.Listen"/>.
/// </summary>
/// <remarks>
/// The listener owns no connection state. When a SYN arrives for its port, <see cref="TcpHost"/> creates a
/// <see cref="TcpConnection"/> in SYN-RECEIVED that points back here. Once the handshake completes, the
/// connection invokes <see cref="Accepted"/>. <see cref="Backlog"/> caps how many handshakes may be pending,
/// which bounds the damage of a SYN flood.
/// </remarks>
public sealed class TcpListener : IDisposable
{
    private readonly TcpHost _host;

    /// <summary>Only <see cref="TcpHost.Listen"/> creates listeners, after validating the arguments and the port.</summary>
    internal TcpListener(TcpHost host, ushort port, Action<TcpConnection> accepted, int backlog, int receiveCapacity)
    {
        _host = host;
        Port = port;
        Accepted = accepted;
        Backlog = backlog;
        ReceiveCapacity = receiveCapacity;
    }

    /// <summary>The local port this listener accepts connections on.</summary>
    public ushort Port { get; }

    /// <summary>Application callback for each connection that completes its handshake, raised just before <see cref="TcpConnection.Connected"/>.</summary>
    internal Action<TcpConnection> Accepted { get; }
    /// <summary>Most half-open (SYN-RECEIVED) connections allowed at once.</summary>
    internal int Backlog { get; }
    /// <summary>Receive buffer size given to each accepted connection.</summary>
    internal int ReceiveCapacity { get; }

    /// <summary>Stops listening: frees the port and aborts handshakes still pending. Established connections are unaffected.</summary>
    public void Dispose() => _host.Stop(this);
}
