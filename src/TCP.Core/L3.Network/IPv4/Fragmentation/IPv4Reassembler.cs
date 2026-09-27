using System.Net;

namespace TCP.L3.Network.IPv4.Fragmentation;

/// <summary>Bounded per-interface reassembly with fixed lifetimes and overlap rejection.</summary>
/// <remarks>
/// <para>
/// A datagram larger than some link's MTU travels as fragments: pieces of its payload, each with a copy of the
/// header, placed by an 8-byte-unit offset and marked "more fragments" except the last (RFC 791 2.3, 3.2).
/// <see cref="IPv4Host"/> passes every received datagram through <see cref="TryAccept(IPv4Packet, bool, out IPv4Packet, out bool, out IPv4Packet)"/>.
/// Whole datagrams go straight through; fragments are held until their datagram is complete.
/// </para>
/// <para>
/// Fragments are a classic attack surface, so this reassembler is strict:
/// </para>
/// <list type="bullet">
/// <item>any overlap poisons the whole datagram (RFC 5722 applies the same rule to IPv6);</item>
/// <item>inconsistent final lengths and mixed ECN codepoints are rejected (RFC 3168 5.3);</item>
/// <item>at most 128 datagrams may be pending, each for at most 60 seconds.</item>
/// </list>
/// <para>
/// A rejected datagram stays remembered until it expires, so later fragments of it are dropped too.
/// </para>
/// </remarks>
/// <param name="timeProvider">Clock for reassembly lifetimes; the system clock when null.</param>
public sealed class IPv4Reassembler(TimeProvider? timeProvider = null)
{
    private const int MaximumPendingAssemblies = 128;
    private const ushort InvalidFragmentFlagsMask =
        IPv4FragmentField.ReservedFlag | IPv4FragmentField.DontFragmentFlag;
    private const ushort UnfragmentedPacketMask = IPv4FragmentField.ReassemblyMask;
    private const byte EcnFieldMask = 0b0000_0011;
    private const byte DscpFieldMask = 0b1111_1100;
    private const int NotEctSeenMask = 1 << 0;
    private const int EctOneSeenMask = 1 << 1;
    private const int EctZeroSeenMask = 1 << 2;
    private const int CongestionExperiencedSeenMask = 1 << 3;
    private const int NotEct = 0;
    private const int EctOne = 1;
    private const int EctZero = 2;
    private const int CongestionExperienced = 3;
    private static readonly TimeSpan ReassemblyLifetime = TimeSpan.FromSeconds(60);

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly Dictionary<Key, Assembly> _pending = [];

    /// <summary>Fragments belong to the same datagram when source, destination, protocol and identification all match (RFC 791).</summary>
    private readonly record struct Key(IPAddress Source, IPAddress Destination, byte Protocol, ushort Id);

    /// <summary>A datagram whose fragments did not all arrive in time.</summary>
    /// <param name="FirstFragment">The offset-zero fragment, quoted in the ICMP Time Exceeded error.</param>
    /// <param name="LinkBroadcast">Whether any fragment arrived as a link broadcast, in which case no error may be sent.</param>
    public sealed record Expired(IPv4Packet FirstFragment, bool LinkBroadcast);

    /// <summary>One arriving fragment's placement within its datagram's payload.</summary>
    private readonly record struct Fragment(int Offset, int End, bool MoreFragments, ReadOnlyMemory<byte> Payload)
    {
        /// <summary>Decodes the offset (8-byte units to bytes) and the MF flag from the packet's header.</summary>
        public static Fragment From(IPv4Packet packet)
        {
            var offset = (packet.FlagsAndFragmentOffset & IPv4FragmentField.FragmentOffsetMask) * IPv4FragmentField.OffsetUnitLength;
            var moreFragments = (packet.FlagsAndFragmentOffset & IPv4FragmentField.MoreFragmentsFlag) != 0;
            return new Fragment(offset, offset + packet.Payload.Length, moreFragments, packet.Payload);
        }

        /// <summary>The final fragment: its end fixes the datagram's total payload length.</summary>
        public bool IsLast => !MoreFragments;
    }

    /// <summary>The pieces collected so far for one datagram.</summary>
    private sealed class Assembly(DateTimeOffset expiresAt)
    {
        /// <summary>Fixed when the first fragment arrives; later fragments do not extend it.</summary>
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        /// <summary>The offset-zero fragment, whose header becomes the reassembled datagram's header.</summary>
        public IPv4Packet? FirstFragment { get; set; }
        /// <summary>Any fragment arrived as a link broadcast; errors about the datagram are then suppressed.</summary>
        public bool LinkBroadcast { get; set; }
        /// <summary>Payload pieces by byte offset, sorted so completeness is a single in-order scan.</summary>
        public SortedDictionary<int, byte[]> Pieces { get; } = [];
        /// <summary>Each stored piece's MF flag, so a "duplicate" that changes the flag is recognized as a conflict.</summary>
        public Dictionary<int, bool> MoreFragmentsByOffset { get; } = [];
        /// <summary>Total payload length, known once the last fragment arrives.</summary>
        public int? FinalPayloadLength { get; set; }
        /// <summary>One bit per ECN codepoint seen across the fragments, used to detect mixing and to choose the reassembled codepoint.</summary>
        public int EcnCodepointsSeenMask { get; set; }
        /// <summary>Poisoned by a bad fragment; its later fragments are dropped until it expires.</summary>
        public bool Rejected { get; set; }
    }

    /// <summary>
    /// Discards datagrams whose lifetime has passed. Returns those that had their first fragment and were never
    /// rejected, so the host can send ICMP "fragment reassembly time exceeded" (RFC 792).
    /// </summary>
    public IEnumerable<Expired> Expire()
    {
        foreach (var (key, assembly) in _pending.ToArray())
        {
            if (assembly.ExpiresAt > _time.GetUtcNow()) continue;
            _pending.Remove(key);
            if (!assembly.Rejected && assembly.FirstFragment is { } firstFragment)
                yield return new Expired(firstFragment, assembly.LinkBroadcast);
        }
    }

    /// <inheritdoc cref="TryAccept(IPv4Packet, bool, out IPv4Packet, out bool, out IPv4Packet)"/>
    public bool TryAccept(IPv4Packet packet, bool linkBroadcast, out IPv4Packet complete, out bool wasBroadcast)
        => TryAccept(packet, linkBroadcast, out complete, out wasBroadcast, out _);

    /// <summary>Offers a received datagram, which may be a fragment, for reassembly.</summary>
    /// <param name="packet">The datagram as received.</param>
    /// <param name="linkBroadcast">Whether it arrived as a link-layer broadcast or multicast.</param>
    /// <param name="complete">The whole datagram when this returns true.</param>
    /// <param name="wasBroadcast">Whether any piece of the complete datagram arrived as a broadcast.</param>
    /// <param name="firstFragment">The offset-zero fragment of the complete datagram, whose header ICMP errors must quote.</param>
    /// <returns>True when <paramref name="complete"/> holds a datagram ready for delivery.</returns>
    public bool TryAccept(
        IPv4Packet packet,
        bool linkBroadcast,
        out IPv4Packet complete,
        out bool wasBroadcast,
        out IPv4Packet firstFragment)
    {
        firstFragment = packet;
        complete = default;
        wasBroadcast = linkBroadcast;

        if ((packet.FlagsAndFragmentOffset & UnfragmentedPacketMask) == 0)
        {
            complete = packet;
            return true;
        }

        var key = new Key(packet.SourceAddress, packet.DestinationAddress, packet.Protocol, packet.Identification);
        if (!TryGetOrStartAssembly(key, out var assembly) || assembly.Rejected) return false;
        assembly.LinkBroadcast |= linkBroadcast;
        if (!TryAddFragment(assembly, packet)) return false;
        if (!TryConcatenate(assembly, out var payload)) return false;

        var first = assembly.FirstFragment!.Value;
        firstFragment = first;
        complete = first with
        {
            Payload = payload,
            FlagsAndFragmentOffset = 0,
            TypeOfService = (byte)((first.TypeOfService & DscpFieldMask) | ReassembledEcn(assembly.EcnCodepointsSeenMask))
        };
        wasBroadcast = assembly.LinkBroadcast;
        _pending.Remove(key);
        return true;
    }

    /// <returns>False when the pending table is full, which drops the fragment.</returns>
    private bool TryGetOrStartAssembly(Key key, out Assembly assembly)
    {
        if (_pending.TryGetValue(key, out assembly!)) return true;
        if (_pending.Count >= MaximumPendingAssemblies) return false;
        assembly = new Assembly(_time.GetUtcNow() + ReassemblyLifetime);
        _pending[key] = assembly;
        return true;
    }

    /// <summary>
    /// Validates the fragment against everything known about its datagram and stores it. Any inconsistency
    /// rejects the whole datagram. An exact duplicate is dropped without harm.
    /// </summary>
    /// <returns>True when the fragment was stored.</returns>
    private static bool TryAddFragment(Assembly assembly, IPv4Packet packet)
    {
        var fragment = Fragment.From(packet);
        if (IsMalformed(fragment, packet) || ContradictsFinalLength(assembly, fragment)) return Reject(assembly);

        if (fragment.IsLast)
        {
            if (assembly.Pieces.Any(piece => piece.Key + piece.Value.Length > fragment.End)) return Reject(assembly);
            assembly.FinalPayloadLength = fragment.End;
        }

        switch (FindCollision(assembly, fragment))
        {
            case Collision.Duplicate: return false;
            case Collision.Conflict: return Reject(assembly);
        }

        if (fragment.Offset == 0) assembly.FirstFragment = packet;
        if (ExceedsMaximumDatagram(assembly, fragment) || MixesEcnCodepoints(assembly, packet)) return Reject(assembly);

        assembly.Pieces[fragment.Offset] = packet.Payload.ToArray();
        assembly.MoreFragmentsByOffset[fragment.Offset] = fragment.MoreFragments;
        return true;
    }

    /// <summary>
    /// Structural errors: an empty fragment, one reaching past the largest possible payload, a non-final
    /// fragment whose length is not a multiple of 8 bytes, or the reserved or Don't Fragment flag set.
    /// </summary>
    private static bool IsMalformed(Fragment fragment, IPv4Packet packet) =>
        packet.Payload.IsEmpty ||
        fragment.End > IPv4Packet.MaximumPayloadLength ||
        (fragment.MoreFragments && packet.Payload.Length % IPv4FragmentField.OffsetUnitLength != 0) ||
        (packet.FlagsAndFragmentOffset & InvalidFragmentFlagsMask) != 0;

    /// <summary>Once the last fragment has fixed the length, nothing may extend past it and no second "last" may disagree.</summary>
    private static bool ContradictsFinalLength(Assembly assembly, Fragment fragment) =>
        assembly.FinalPayloadLength is { } finalLength &&
        (fragment.End > finalLength ||
         (fragment.MoreFragments && fragment.End >= finalLength) ||
         (fragment.IsLast && finalLength != fragment.End));

    /// <summary>How an arriving fragment relates to the pieces already held.</summary>
    private enum Collision
    {
        /// <summary>No overlap; the fragment fills new space.</summary>
        None,
        /// <summary>An exact retransmission of a stored piece; drop it quietly.</summary>
        Duplicate,
        /// <summary>A partial or differing overlap; reject the whole datagram.</summary>
        Conflict
    }

    /// <summary>
    /// Compares the fragment with the pieces already held, in offset order. An identical retransmission is a
    /// duplicate; any other overlap is a conflict (possibly an attack to smuggle different bytes).
    /// </summary>
    private static Collision FindCollision(Assembly assembly, Fragment fragment)
    {
        foreach (var (offset, payload) in assembly.Pieces)
        {
            if (offset == fragment.Offset && payload.AsSpan().SequenceEqual(fragment.Payload.Span))
                return assembly.MoreFragmentsByOffset[offset] == fragment.MoreFragments ? Collision.Duplicate : Collision.Conflict;
            if (offset < fragment.End && offset + payload.Length > fragment.Offset) return Collision.Conflict;
        }
        return Collision.None;
    }

    /// <summary>With the first fragment's header known, the reassembled datagram must still fit in 65,535 bytes.</summary>
    private static bool ExceedsMaximumDatagram(Assembly assembly, Fragment fragment)
    {
        if (assembly.FirstFragment is not { } first) return false;
        var limit = IPv4Packet.MaximumTotalLength - first.HeaderLength;
        return fragment.End > limit || assembly.Pieces.Any(piece => piece.Key + piece.Value.Length > limit);
    }

    /// <summary>
    /// Records this fragment's ECN codepoint. Mixing Not-ECT with any ECN-capable codepoint means a middlebox
    /// mangled the datagram, so it must be discarded (RFC 3168 5.3).
    /// </summary>
    private static bool MixesEcnCodepoints(Assembly assembly, IPv4Packet packet)
    {
        assembly.EcnCodepointsSeenMask |= 1 << (packet.TypeOfService & EcnFieldMask);
        return (assembly.EcnCodepointsSeenMask & NotEctSeenMask) != 0 && assembly.EcnCodepointsSeenMask != NotEctSeenMask;
    }

    /// <summary>
    /// The ECN codepoint for the whole datagram: Congestion Experienced if any fragment saw congestion, else the
    /// ECT codepoint the fragments carried (RFC 3168 5.3).
    /// </summary>
    private static int ReassembledEcn(int seenMask)
    {
        if ((seenMask & CongestionExperiencedSeenMask) != 0) return CongestionExperienced;
        if ((seenMask & EctZeroSeenMask) != 0) return EctZero;
        if ((seenMask & EctOneSeenMask) != 0) return EctOne;
        return NotEct;
    }

    /// <summary>Builds the payload once the first and last fragments are present and the pieces leave no gaps.</summary>
    private static bool TryConcatenate(Assembly assembly, out byte[] payload)
    {
        payload = [];
        if (assembly.FirstFragment is null || assembly.FinalPayloadLength is not { } length) return false;
        if (!IsContiguous(assembly, length)) return false;

        payload = new byte[length];
        foreach (var (offset, piece) in assembly.Pieces) piece.CopyTo(payload, offset);
        return true;
    }

    /// <summary>Each piece starts exactly where the previous ended, and together they reach the final length.</summary>
    private static bool IsContiguous(Assembly assembly, int length)
    {
        var nextExpectedOffset = 0;
        foreach (var (offset, piece) in assembly.Pieces)
        {
            if (offset != nextExpectedOffset) return false;
            nextExpectedOffset += piece.Length;
        }
        return nextExpectedOffset == length;
    }

    /// <summary>Poisons the datagram: frees its pieces but keeps the entry so later fragments are dropped too.</summary>
    /// <returns>Always false, so callers can <c>return Reject(...)</c>.</returns>
    private static bool Reject(Assembly assembly)
    {
        assembly.Rejected = true;
        assembly.Pieces.Clear();
        assembly.MoreFragmentsByOffset.Clear();
        assembly.FirstFragment = null;
        return false;
    }
}
