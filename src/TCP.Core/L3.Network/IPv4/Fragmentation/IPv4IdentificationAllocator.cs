namespace TCP.L3.Network.IPv4.Fragmentation;

/// <summary>
/// Hands out IPv4 Identification values for datagrams that may be fragmented, never reusing one while an
/// earlier datagram with it could still be in the network (RFC 6864 4.1).
/// </summary>
/// <remarks>
/// Reassembly matches fragments by (source, destination, protocol, Identification). If an Identification were
/// reused within a datagram's lifetime, fragments of two different datagrams could be spliced together. The
/// 16-bit space therefore limits how many fragmentable datagrams a host may send per lifetime. Exhausting it is
/// reported rather than risked. Datagrams with Don't Fragment set are never fragmented and do not consume values.
/// </remarks>
internal sealed class IPv4IdentificationAllocator
{
    private const int IdentifierSpace = ushort.MaxValue + 1;

    private readonly Dictionary<ushort, DateTimeOffset> _inUseUntil = [];
    private ushort _next = (ushort)Random.Shared.Next(IdentifierSpace);

    /// <summary>Returns the next Identification not in use at <paramref name="now"/> and reserves it for one datagram lifetime.</summary>
    /// <exception cref="InvalidOperationException">All 65,536 values are in use.</exception>
    public ushort Allocate(DateTimeOffset now)
    {
        for (var attempt = 0; attempt < IdentifierSpace; attempt++)
        {
            var identifier = _next++;
            if (_inUseUntil.TryGetValue(identifier, out var expiresAt) && expiresAt > now) continue;
            _inUseUntil[identifier] = now + IPv4Constants.MaximumDatagramLifetime;
            return identifier;
        }
        throw new InvalidOperationException("IPv4 identification space exhausted; wait for old datagrams to expire.");
    }
}
