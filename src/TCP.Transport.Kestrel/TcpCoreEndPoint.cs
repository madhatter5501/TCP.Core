using System.Net;
using System.Net.Sockets;

namespace TCP.Transport.Kestrel;

/// <summary>A Kestrel endpoint served by the in-process TCP.Core stack.</summary>
public sealed class TcpCoreEndPoint(IPAddress address, int port) : EndPoint
{
    public IPAddress Address { get; } = address.AddressFamily == AddressFamily.InterNetwork
        ? address
        : throw new ArgumentException("TCP.Core currently supports IPv4 endpoints only.", nameof(address));
    public int Port { get; } = port is > IPEndPoint.MinPort and <= IPEndPoint.MaxPort
        ? port
        : throw new ArgumentOutOfRangeException(nameof(port));
    public override AddressFamily AddressFamily => AddressFamily.InterNetwork;
    public override string ToString() => $"tcp-core://{Address}:{Port}";
}
