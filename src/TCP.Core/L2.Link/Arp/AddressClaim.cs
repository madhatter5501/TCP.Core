using System.Net;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Arp;

/// <summary>RFC 5227 probing, announcements, and ongoing conflict defense for a configured address.</summary>
/// <remarks>
/// <para>
/// Two hosts configured with the same IPv4 address silently break each other. Before using its address, the stack
/// asks "does anyone have this?" three times with ARP probes (sender address 0.0.0.0, so no neighbor learns a
/// mapping yet). If nobody answers, it announces the address twice and becomes <see cref="Ready"/>.
/// </para>
/// <para>
/// Afterwards it defends the address. When another host claims it, it re-announces once. A second conflict within
/// 10 seconds makes it give up the address (RFC 5227 2.4(b)).
/// </para>
/// <para>
/// <see cref="Stack.EthernetStack"/> drives <see cref="Tick"/> and feeds every ARP packet to <see cref="Observe"/>.
/// No IP traffic flows until the claim is ready.
/// </para>
/// </remarks>
/// <param name="address">The IPv4 address being claimed.</param>
/// <param name="mac">This interface's hardware address.</param>
/// <param name="broadcast">Sends an ARP packet to the Ethernet broadcast address.</param>
/// <param name="timeProvider">Clock for probe timing; the system clock when null.</param>
/// <param name="random">Source of uniform [0, 1) values for randomized delays; injectable for tests.</param>
public sealed class AddressClaim(IPAddress address, MacAddress mac, Action<ArpPacket> broadcast,
    TimeProvider? timeProvider = null, Func<double>? random = null)
{
    // RFC 5227 section 1.1 timing constants, in seconds.
    private const double ProbeWaitSeconds = 1;
    private const int ProbeCount = 3;
    private const double ProbeMinimumSeconds = 1;
    private const double ProbeMaximumSeconds = 2;
    private const double AnnounceWaitSeconds = 2;
    private const int AnnounceCount = 2;
    private const double AnnounceIntervalSeconds = 2;
    private static readonly TimeSpan DefendInterval = TimeSpan.FromSeconds(10);

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly Func<double> _random = random ?? Random.Shared.NextDouble;
    private DateTimeOffset? _next;
    private DateTimeOffset? _lastDefense;
    private int _probes;
    private int _announcements;

    /// <summary>The probes found no conflict and the address is announced: the host may use it.</summary>
    public bool Ready { get; private set; }

    /// <summary>Sends the next probe or announcement when its time has come. Call regularly from the stack's loop.</summary>
    public void Tick()
    {
        var now = _time.GetUtcNow();
        _next ??= now + Seconds(ProbeWaitSeconds * _random());
        if (now < _next || _announcements == AnnounceCount) return;
        if (_probes < ProbeCount) SendProbe(now);
        else SendAnnouncement(now);
    }

    /// <summary>Checks an incoming ARP packet for a conflict with our address.</summary>
    /// <exception cref="InvalidOperationException">
    /// The address is taken: someone claimed it while we were probing, or claimed it twice within the defend interval.
    /// </exception>
    public void Observe(ArpPacket packet)
    {
        if (packet.SenderHardwareAddress == mac || !IsConflict(packet)) return;
        if (!Ready) throw new InvalidOperationException($"IPv4 address {address} is already in use; choose another address.");
        Defend();
    }

    /// <summary>
    /// Another host uses our address as its sender, or, while we are still probing, another host is probing for
    /// the same address at the same time.
    /// </summary>
    private bool IsConflict(ArpPacket packet)
    {
        var claimsAddress = packet.SenderProtocolAddress.Equals(address);
        var competingProbe = packet.Operation == ArpOperation.Request &&
            packet.SenderProtocolAddress.Equals(IPAddress.Any) && packet.TargetProtocolAddress.Equals(address);
        return claimsAddress || (!Ready && competingProbe);
    }

    /// <summary>
    /// RFC 5227 2.4(b): re-announce once to reassert ownership. A second conflict within the defend interval
    /// means the other host insists, so stop using the address.
    /// </summary>
    private void Defend()
    {
        var now = _time.GetUtcNow();
        if (_lastDefense is { } previous && now - previous < DefendInterval)
        {
            Ready = false;
            throw new InvalidOperationException($"Repeated conflict for {address}; the stack has stopped using it.");
        }
        _lastDefense = now;
        Announce();
    }

    /// <summary>
    /// An ARP request for our address with a sender address of 0.0.0.0, so it asks without claiming. Probes are
    /// spaced 1-2 seconds apart at random, and the last is followed by the announce wait.
    /// </summary>
    private void SendProbe(DateTimeOffset now)
    {
        broadcast(new ArpPacket(ArpOperation.Request, mac, IPAddress.Any, default, address));
        _probes++;
        var delay = _probes == ProbeCount
            ? AnnounceWaitSeconds
            : ProbeMinimumSeconds + _random() * (ProbeMaximumSeconds - ProbeMinimumSeconds);
        _next = now + Seconds(delay);
    }

    /// <summary>Claims the address publicly; the first announcement makes the address ready for use.</summary>
    private void SendAnnouncement(DateTimeOffset now)
    {
        Announce();
        _announcements++;
        Ready = true;
        _next = now + Seconds(AnnounceIntervalSeconds);
    }

    /// <summary>A gratuitous ARP: a request whose sender and target are both our address, updating every neighbor's cache.</summary>
    private void Announce() => broadcast(ArpPacket.CreateRequest(mac, address, address));

    /// <summary>Shorthand for the RFC's timing constants, which are given in seconds.</summary>
    private static TimeSpan Seconds(double seconds) => TimeSpan.FromSeconds(seconds);
}
