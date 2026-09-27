using System.Net;
using Microsoft.AspNetCore.Connections;

namespace TCP.Transport.Kestrel;

/// <summary>Kestrel listener transport that binds endpoints to TCP.Core.</summary>
public sealed class TcpCoreConnectionListenerFactory(
    TcpCoreHostService host,
    TcpCoreServerOptions options) : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is TcpCoreEndPoint;

    public async ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not TcpCoreEndPoint tcpEndpoint)
            throw new NotSupportedException($"TCP.Core cannot bind endpoint type {endpoint.GetType().Name}.");
        if (!tcpEndpoint.Address.Equals(options.Address))
            throw new InvalidOperationException("The TCP.Core Kestrel endpoint must use the configured stack IPv4 address.");
        var tcpHost = await host.GetTcpHostAsync(cancellationToken);
        var listener = new TcpCoreConnectionListener(host, tcpHost, options, tcpEndpoint);
        await host.RunOnProtocolThreadAsync(listener.Bind, cancellationToken);
        return listener;
    }
}
