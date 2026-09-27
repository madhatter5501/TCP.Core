using System.Net;

namespace TCP.L3.Network.IPv4.Routing;

/// <summary>Routes and expiring redirect entries for one interface. ARP resolves the selected next hop.</summary>
/// <remarks>
/// <para>
/// Routing answers "to reach this destination, which neighbor do I hand the datagram to, and how big may it be?"
/// Lookup picks the longest matching prefix, breaking ties by lowest metric. The connected subnet is always
/// present and delivers directly; other routes name an on-link gateway.
/// </para>
/// <para>
/// Two kinds of learned state refine the answer:
/// </para>
/// <list type="bullet">
/// <item>ICMP Redirects, which override the gateway for one destination for 10 minutes (RFC 1122 3.3.1.2).</item>
/// <item>Gateways marked unreachable after ARP failures, which are skipped for 30 seconds so a working
/// alternative can be used (dead gateway detection, RFC 1122 3.3.1.4).</item>
/// </list>
/// <para>Both tables are bounded.</para>
/// </remarks>
public sealed class IPv4RouteTable
{
    private const int MaximumRouteCount = 1024;
    private const int MaximumRedirectCount = 1024;
    private static readonly TimeSpan RedirectLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan UnreachableGatewayLifetime = TimeSpan.FromSeconds(30);

    private readonly IPv4Subnet _connected;
    private readonly List<IPv4Route> _routes;
    private readonly TimeProvider _time;
    private readonly Dictionary<IPAddress, (IPAddress Gateway, DateTimeOffset Expires)> _redirects = [];
    private readonly Dictionary<IPAddress, DateTimeOffset> _unreachableUntil = [];

    /// <summary>Creates a table holding only the connected route.</summary>
    /// <param name="connected">The subnet this interface is directly attached to.</param>
    /// <param name="mtu">MTU of the connected route.</param>
    /// <param name="timeProvider">Clock for redirect and unreachable-gateway expiry; the system clock when null.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="mtu"/> is outside 68..65535.</exception>
    public IPv4RouteTable(IPv4Subnet connected, int mtu = IPv4Constants.DefaultMtu, TimeProvider? timeProvider = null)
    {
        if (!IsValidMtu(mtu)) throw new ArgumentOutOfRangeException(nameof(mtu));
        _connected = connected;
        _routes = [new IPv4Route(connected, null, mtu)];
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Current time, for expiring redirects and unreachable-gateway marks.</summary>
    private DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>Adds a static route, such as a default route through a gateway.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The route's MTU is out of range.</exception>
    /// <exception cref="ArgumentException">The gateway is not a usable address on the connected subnet.</exception>
    /// <exception cref="InvalidOperationException">The table is full.</exception>
    public void Add(IPv4Route route)
    {
        if (!IsValidMtu(route.Mtu)) throw new ArgumentOutOfRangeException(nameof(route));
        if (route.Gateway is not null && !_connected.TryGetNextHop(route.Gateway, out _))
            throw new ArgumentException("A gateway must be a usable address on the connected subnet.", nameof(route));
        if (_routes.Count >= MaximumRouteCount) throw new InvalidOperationException("Route table is full.");
        _routes.Add(route);
    }

    /// <summary>Chooses how to reach <paramref name="destination"/>.</summary>
    /// <param name="destination">The datagram's destination address.</param>
    /// <param name="nextHop">The on-link neighbor to send to: a gateway, a redirect target, or the destination itself.</param>
    /// <param name="routeMtu">The chosen route's MTU; 0 when there is no route.</param>
    /// <returns>False when no route matches.</returns>
    public bool TryLookup(IPAddress destination, out IPAddress nextHop, out int routeMtu)
    {
        var now = Now;
        var route = BestRoute(destination, now);
        nextHop = route?.Gateway ?? destination;
        routeMtu = route?.Mtu ?? 0;
        if (route is null) return false;
        if (!_connected.Contains(destination) && TryGetLiveRedirect(destination, now, out var redirectGateway)) nextHop = redirectGateway;
        return true;
    }

    /// <summary>
    /// Applies an ICMP Redirect. It is believed only when it comes from the gateway we currently use for that
    /// destination, names a usable on-link gateway, and concerns an off-link destination.
    /// </summary>
    /// <param name="sender">Source of the Redirect message.</param>
    /// <param name="destination">The destination the Redirect is about.</param>
    /// <param name="newGateway">The better first hop it proposes.</param>
    /// <returns>Whether the redirect was recorded.</returns>
    public bool ApplyRedirect(IPAddress sender, IPAddress destination, IPAddress newGateway)
    {
        if (!IsBelievableRedirect(sender, destination, newGateway)) return false;
        if (_redirects.Count >= MaximumRedirectCount && !_redirects.ContainsKey(destination)) EvictOldestRedirect();
        _redirects[destination] = (newGateway, Now + RedirectLifetime);
        return true;
    }

    /// <summary>
    /// Marks a gateway as unreachable after address resolution fails, so lookups avoid it for a while. Addresses
    /// that are not gateways (plain on-link hosts) are ignored.
    /// </summary>
    public void MarkUnreachable(IPAddress gateway)
    {
        var isConfiguredGateway = _routes.Any(route => route.Gateway?.Equals(gateway) == true);
        var isRedirectGateway = _redirects.Values.Any(redirect => redirect.Gateway.Equals(gateway));
        if (isConfiguredGateway || isRedirectGateway) _unreachableUntil[gateway] = Now + UnreachableGatewayLifetime;
    }

    /// <summary>Between the IPv4 minimum link MTU (68) and the largest datagram (65,535).</summary>
    private static bool IsValidMtu(int mtu) => mtu is >= IPv4Constants.MinimumMtu and <= IPv4Packet.MaximumTotalLength;

    /// <summary>Longest prefix wins, then lowest metric; routes through a gateway currently marked unreachable are skipped.</summary>
    private IPv4Route? BestRoute(IPAddress destination, DateTimeOffset now) =>
        _routes
            .Where(route => route.Network.Contains(destination) && (route.Gateway is null || IsGatewayAvailable(route.Gateway, now)))
            .OrderByDescending(route => route.Network.PrefixLength)
            .ThenBy(route => route.Metric)
            .FirstOrDefault();

    /// <summary>Not marked unreachable, or its mark has expired and it may be tried again.</summary>
    private bool IsGatewayAvailable(IPAddress gateway, DateTimeOffset now) =>
        !_unreachableUntil.TryGetValue(gateway, out var unavailableUntil) || unavailableUntil <= now;

    /// <summary>Finds a redirect for the destination, discarding it if it has expired or its gateway is unreachable.</summary>
    private bool TryGetLiveRedirect(IPAddress destination, DateTimeOffset now, out IPAddress gateway)
    {
        gateway = destination;
        if (!_redirects.TryGetValue(destination, out var redirect)) return false;
        if (redirect.Expires > now && IsGatewayAvailable(redirect.Gateway, now))
        {
            gateway = redirect.Gateway;
            return true;
        }
        _redirects.Remove(destination);
        return false;
    }

    /// <summary>
    /// RFC 1122 3.2.2.2: the destination is off-link, the new gateway is on-link, and the sender is the gateway we
    /// would currently use. Anything else is ignored as possibly forged.
    /// </summary>
    private bool IsBelievableRedirect(IPAddress sender, IPAddress destination, IPAddress newGateway) =>
        !_connected.Contains(destination) &&
        _connected.TryGetNextHop(newGateway, out _) &&
        TryLookup(destination, out var currentNextHop, out _) &&
        currentNextHop.Equals(sender);

    /// <summary>Makes room in a full redirect table by dropping the entry closest to expiry.</summary>
    private void EvictOldestRedirect() => _redirects.Remove(_redirects.MinBy(entry => entry.Value.Expires).Key);
}
