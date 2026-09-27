using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TCP.Stack;

namespace TCP.Transport.Kestrel;

public static class TcpCoreTransportRegistration
{
    /// <summary>
    /// Serves Kestrel endpoints of type <see cref="TcpCoreEndPoint"/> through TCP.Core on a real interface.
    /// Other endpoint types keep using Kestrel's default socket transport.
    /// </summary>
    public static IServiceCollection AddTcpCoreTransport(this IServiceCollection services, TcpCoreServerOptions options)
        => AddTcpCoreTransport(services, options, null);

    /// <summary>Test seam: supply the stack, for example one attached to a virtual Ethernet link.</summary>
    internal static IServiceCollection AddTcpCoreTransport(
        this IServiceCollection services, TcpCoreServerOptions options, Func<EthernetStack>? stackFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        services.AddSingleton(options);
        services.AddSingleton(provider => new TcpCoreHostService(options, stackFactory, provider.GetService<IHostApplicationLifetime>()));
        services.AddSingleton<IHostedService>(provider => provider.GetRequiredService<TcpCoreHostService>());
        services.AddSingleton<TcpCoreConnectionListenerFactory>();
        services.AddSingleton<IConnectionListenerFactory>(provider => provider.GetRequiredService<TcpCoreConnectionListenerFactory>());
        return services;
    }
}
