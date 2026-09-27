using System.Net;
using System.Net.Sockets;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Arp;

/// <summary>A bounded neighbor table owned by one interface, with expiring dynamic entries.</summary>
/// <remarks>
/// Maps on-link IPv4 addresses to MAC addresses, as learned from ARP (RFC 826). Entries expire so a neighbor that
/// changes its network card, or disappears, is re-resolved instead of receiving frames forever. When the table
/// is full, the entry closest to expiry is replaced.
/// </remarks>
/// <param name="timeProvider">Clock for expiry; the system clock when null.</param>
/// <param name="lifetime">How long a learned mapping stays valid; one minute when null.</param>
/// <param name="capacity">Most neighbors remembered at once.</param>
public sealed class ArpCache(TimeProvider? timeProvider = null, TimeSpan? lifetime = null, int capacity = 1024)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly TimeSpan _lifetime = lifetime ?? TimeSpan.FromMinutes(1);
    private readonly Dictionary<IPAddress, Entry> _entries = [];

    /// <summary>A learned hardware address and when it stops being trusted.</summary>
    private sealed record Entry(MacAddress Mac, DateTimeOffset Expires);

    /// <summary>Number of unexpired entries.</summary>
    public int Count
    {
        get
        {
            Expire();
            return _entries.Count;
        }
    }

    /// <summary>Stores or refreshes a neighbor's hardware address.</summary>
    /// <exception cref="ArgumentException">The address is not IPv4, or the MAC is not unicast.</exception>
    /// <exception cref="InvalidOperationException">The cache was created with a non-positive capacity or lifetime.</exception>
    public void Remember(IPAddress address, MacAddress hardwareAddress)
    {
        ValidateIPv4(address);
        if (hardwareAddress == default || hardwareAddress.IsMulticast)
            throw new ArgumentException("A neighbor must have a unicast MAC address.", nameof(hardwareAddress));
        Expire();
        if (capacity < 1 || _lifetime <= TimeSpan.Zero) throw new InvalidOperationException("Invalid cache limits.");
        if (_entries.Count >= capacity && !_entries.ContainsKey(address)) EvictSoonestToExpire();
        _entries[address] = new Entry(hardwareAddress, _time.GetUtcNow() + _lifetime);
    }

    /// <summary>Looks up a neighbor's hardware address, discarding the entry if it has expired.</summary>
    public bool TryResolve(IPAddress address, out MacAddress hardwareAddress)
    {
        ValidateIPv4(address);
        if (_entries.TryGetValue(address, out var entry) && entry.Expires > _time.GetUtcNow())
        {
            hardwareAddress = entry.Mac;
            return true;
        }
        _entries.Remove(address);
        hardwareAddress = default;
        return false;
    }

    /// <summary>Removes a neighbor's entry.</summary>
    /// <returns>Whether an entry existed.</returns>
    public bool Forget(IPAddress address) => _entries.Remove(address);

    /// <summary>Removes every entry whose lifetime has passed.</summary>
    private void Expire()
    {
        var now = _time.GetUtcNow();
        foreach (var address in _entries.Where(pair => pair.Value.Expires <= now).Select(pair => pair.Key).ToArray())
            _entries.Remove(address);
    }

    /// <summary>Makes room in a full cache by dropping the entry that would expire first.</summary>
    private void EvictSoonestToExpire() => _entries.Remove(_entries.MinBy(pair => pair.Value.Expires).Key);

    /// <summary>ARP for Ethernet maps IPv4 only; anything else is a caller bug.</summary>
    /// <exception cref="ArgumentException">Not an IPv4 address.</exception>
    private static void ValidateIPv4(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("The ARP cache only stores IPv4 addresses.", nameof(address));
    }
}
