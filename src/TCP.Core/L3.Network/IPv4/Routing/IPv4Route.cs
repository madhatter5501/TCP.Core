using System.Net;

namespace TCP.L3.Network.IPv4.Routing;

/// <summary>One entry in the <see cref="IPv4RouteTable"/>: how to reach a range of destinations.</summary>
/// <param name="Network">The destinations this route covers; a /0 network makes a default route.</param>
/// <param name="Gateway">The on-link router to send through, or null to deliver directly (the connected route).</param>
/// <param name="Mtu">Largest datagram to send along this route before fragmenting.</param>
/// <param name="Metric">Preference among routes with equal prefix length; lower wins.</param>
public sealed record IPv4Route(IPv4Subnet Network, IPAddress? Gateway, int Mtu, int Metric = 0);