using System.Net;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// Identifies a connection on this host: the TCP four-tuple minus the local address, which is implied
/// by the owning <see cref="TcpHost"/>. <see cref="TcpHost"/> uses it to route each arriving segment
/// to its <see cref="TcpConnection"/> and to keep port pairs unique.
/// </summary>
/// <param name="LocalPort">Our port.</param>
/// <param name="RemoteAddress">The peer's IPv4 address.</param>
/// <param name="RemotePort">The peer's port.</param>
internal readonly record struct ConnectionKey(ushort LocalPort, IPAddress RemoteAddress, ushort RemotePort);
