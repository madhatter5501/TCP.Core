using System.Net;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp;

namespace TCP.Transport.Kestrel;

/// <summary>Explicit configuration for serving Kestrel through a TCP.Core Ethernet stack.</summary>
public sealed class TcpCoreServerOptions
{
    /// <summary>Ethernet interface the stack captures and injects frames on, such as <c>en0</c>.</summary>
    public required string InterfaceName { get; init; }

    /// <summary>IPv4 address owned by TCP.Core. It must be unused on the network and not assigned to the OS.</summary>
    public required IPAddress Address { get; init; }

    /// <summary>Optional default gateway for clients beyond the interface subnet.</summary>
    public IPAddress? Gateway { get; init; }

    public int Mtu { get; init; } = IPv4Constants.DefaultMtu;
    public int ReceiveCapacity { get; init; } = TcpHost.DefaultReceiveCapacity;

    /// <summary>Handshakes in progress per listener, and accepted connections waiting for Kestrel.</summary>
    public int Backlog { get; init; } = TcpHost.DefaultBacklog;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(InterfaceName);
        ArgumentNullException.ThrowIfNull(Address);
        if (Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("The TCP.Core transport requires an IPv4 address.", nameof(Address));
        if (Gateway is { AddressFamily: not System.Net.Sockets.AddressFamily.InterNetwork })
            throw new ArgumentException("The gateway must be an IPv4 address.", nameof(Gateway));
        ArgumentOutOfRangeException.ThrowIfLessThan(Mtu, IPv4Constants.MinimumMtu, nameof(Mtu));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Mtu, IPv4Packet.MaximumTotalLength, nameof(Mtu));
        ArgumentOutOfRangeException.ThrowIfLessThan(ReceiveCapacity, 1, nameof(ReceiveCapacity));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ReceiveCapacity, TcpHost.MaximumReceiveCapacity, nameof(ReceiveCapacity));
        ArgumentOutOfRangeException.ThrowIfLessThan(Backlog, 1, nameof(Backlog));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Backlog, TcpHost.MaximumBacklog, nameof(Backlog));
    }
}
