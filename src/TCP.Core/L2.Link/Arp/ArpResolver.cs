using System.Net;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Arp;

/// <summary>Single-threaded, per-port resolution. Tick drives retries without blocking reception.</summary>
/// <remarks>
/// <para>
/// IP knows which neighbor to send to by IPv4 address; Ethernet needs the neighbor's MAC address. When the
/// <see cref="ArpCache"/> has the mapping, datagrams go out at once. Otherwise they wait in a small per-neighbor
/// queue while ARP requests are broadcast, once a second, up to three times.
/// </para>
/// <para>
/// The queue is released when <see cref="Learned"/> reports an answer, or dropped with <see cref="ResolutionFailed"/>.
/// Queues are bounded, per neighbor and in number, so traffic to dead addresses cannot exhaust memory
/// (RFC 1122 2.3.2.2).
/// </para>
/// </remarks>
/// <param name="cache">The neighbor table to consult and fill.</param>
/// <param name="request">Broadcasts an ARP request for an address.</param>
/// <param name="transmit">Sends a datagram's bytes to a resolved hardware address.</param>
/// <param name="timeProvider">Clock for retry timing; the system clock when null.</param>
public sealed class ArpResolver(ArpCache cache, Action<IPAddress> request,
    Action<MacAddress, byte[]> transmit, TimeProvider? timeProvider = null)
{
    private const int MaximumPendingNeighbors = 64;
    private const int MaximumQueuedPerNeighbor = 4;
    private const int MaximumRequests = 3;
    private static readonly TimeSpan RequestInterval = TimeSpan.FromSeconds(1);

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly Dictionary<IPAddress, Pending> _pending = [];

    /// <summary>Datagrams waiting for one neighbor's address, and that neighbor's retry state.</summary>
    private sealed class Pending(DateTimeOffset now)
    {
        /// <summary>Serialized datagrams waiting for the neighbor's MAC, oldest first.</summary>
        public Queue<byte[]> Packets { get; } = new();
        /// <summary>When the next request is due; the first is due immediately.</summary>
        public DateTimeOffset Next { get; set; } = now;
        /// <summary>ARP requests sent so far for this neighbor.</summary>
        public int Attempts { get; set; }
    }

    /// <summary>
    /// A neighbor did not answer, or too many resolutions were already pending. Its queued datagrams are
    /// dropped. The stack uses this to mark a dead gateway in the route table.
    /// </summary>
    public event Action<IPAddress>? ResolutionFailed;

    /// <summary>Number of neighbors currently being resolved.</summary>
    public int PendingCount => _pending.Count;

    /// <summary>Sends a datagram to an on-link neighbor, resolving its hardware address first if needed.</summary>
    /// <param name="nextHop">The neighbor's IPv4 address.</param>
    /// <param name="packet">The serialized datagram.</param>
    public void Send(IPAddress nextHop, byte[] packet)
    {
        if (cache.TryResolve(nextHop, out var mac))
        {
            transmit(mac, packet);
            return;
        }
        if (!TryGetOrStartPending(nextHop, out var pending))
        {
            ResolutionFailed?.Invoke(nextHop);
            return;
        }
        // Bound memory while retaining the newest datagrams for this neighbor.
        if (pending.Packets.Count == MaximumQueuedPerNeighbor) pending.Packets.Dequeue();
        pending.Packets.Enqueue(packet);
        Tick();
    }

    /// <summary>Records a mapping learned from ARP and flushes any datagrams that were waiting for it.</summary>
    public void Learned(IPAddress address, MacAddress mac)
    {
        cache.Remember(address, mac);
        if (!_pending.Remove(address, out var pending)) return;
        foreach (var packet in pending.Packets) transmit(mac, packet);
    }

    /// <summary>Sends due ARP requests, and gives up on neighbors that have used all their attempts.</summary>
    public void Tick()
    {
        var now = _time.GetUtcNow();
        foreach (var (address, pending) in _pending.ToArray())
        {
            if (pending.Next > now) continue;
            if (pending.Attempts == MaximumRequests) GiveUp(address);
            else SendRequest(address, pending, now);
        }
    }

    /// <returns>False when too many neighbors are already pending.</returns>
    private bool TryGetOrStartPending(IPAddress nextHop, out Pending pending)
    {
        if (_pending.TryGetValue(nextHop, out pending!)) return true;
        if (_pending.Count >= MaximumPendingNeighbors) return false;
        _pending[nextHop] = pending = new Pending(_time.GetUtcNow());
        return true;
    }

    /// <summary>Broadcasts another request and schedules the next retry one interval later.</summary>
    private void SendRequest(IPAddress address, Pending pending, DateTimeOffset now)
    {
        pending.Attempts++;
        pending.Next = now + RequestInterval;
        request(address);
    }

    /// <summary>Drops the neighbor's queued datagrams and reports that it could not be resolved.</summary>
    private void GiveUp(IPAddress address)
    {
        _pending.Remove(address);
        ResolutionFailed?.Invoke(address);
    }
}
