using System.Net;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.Transport.Kestrel;

internal sealed class TcpCoreConnectionListener : IConnectionListener
{
    private readonly TcpCoreHostService _host;
    private readonly TcpHost _tcpHost;
    private readonly TcpCoreServerOptions _options;
    private readonly Channel<ConnectionContext> _accepted;
    private TcpListener? _listener;
    private volatile bool _unbound;

    public TcpCoreConnectionListener(TcpCoreHostService host, TcpHost tcpHost, TcpCoreServerOptions options, EndPoint endpoint)
    {
        _host = host;
        _tcpHost = tcpHost;
        _options = options;
        EndPoint = endpoint;
        _accepted = Channel.CreateBounded<ConnectionContext>(new BoundedChannelOptions(options.Backlog)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true
        });
    }

    public EndPoint EndPoint { get; }

    public ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default) =>
        AcceptCoreAsync(cancellationToken);

    private async ValueTask<ConnectionContext?> AcceptCoreAsync(CancellationToken cancellationToken)
    {
        try { return await _accepted.Reader.ReadAsync(cancellationToken); }
        catch (ChannelClosedException) { return null; }
    }

    /// <summary>Runs on the protocol thread.</summary>
    public void Bind()
    {
        if (_unbound) throw new InvalidOperationException("TCP.Core listener has already been unbound.");
        _listener = _tcpHost.Listen((ushort)((TcpCoreEndPoint)EndPoint).Port, OnAccepted,
            _options.Backlog, _options.ReceiveCapacity);
    }

    /// <summary>Runs on the protocol thread. A full accept queue resets the new connection rather than blocking TCP.</summary>
    private void OnAccepted(TcpConnection tcp)
    {
        if (_unbound) { tcp.Abort(); return; }
        var context = new TcpCoreConnection(_host, tcp);
        if (!_accepted.Writer.TryWrite(context))
            context.Abort(new ConnectionAbortedException("Kestrel's TCP.Core accept queue is full."));
    }

    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        if (_unbound) return;
        await _host.RunOnProtocolThreadAsync(() =>
        {
            if (_unbound) return;
            _unbound = true;
            _listener?.Dispose();
            _listener = null;
            _accepted.Writer.TryComplete();
        }, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        try { await UnbindAsync(CancellationToken.None); }
        catch (IOException) { } // Protocol thread already stopped; TcpHost disposal released the port.
        _accepted.Writer.TryComplete(); // Release any pending AcceptAsync even if unbinding failed.
        while (_accepted.Reader.TryRead(out var connection))
            await connection.DisposeAsync();
    }
}
