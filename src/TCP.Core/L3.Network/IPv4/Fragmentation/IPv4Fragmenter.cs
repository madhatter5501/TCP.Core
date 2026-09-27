using TCP.L3.Network.IPv4.Options;

namespace TCP.L3.Network.IPv4.Fragmentation;

/// <summary>Splits a datagram into fragments that each fit a link MTU (RFC 791 3.2).</summary>
/// <remarks>
/// <para>
/// Called on the send path by <see cref="IPv4Host.FragmentForTransmit"/> once the link knows the next hop and
/// its MTU. Each fragment repeats the header and carries a slice of the payload. Slices are a multiple of 8
/// bytes except the last, because the offset field counts 8-byte units. The first fragment keeps all options;
/// later ones keep only options marked "copied".
/// </para>
/// <para>
/// A fragment can itself be fragmented again: the pieces inherit its offset and its More Fragments flag.
/// </para>
/// </remarks>
public static class IPv4Fragmenter
{
    /// <summary>Returns the datagram unchanged if it fits <paramref name="mtu"/>, otherwise its fragments in order.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="mtu"/> is outside 68..65535.</exception>
    /// <exception cref="ArgumentException">The datagram exceeds 65,535 bytes.</exception>
    /// <exception cref="InvalidOperationException">The datagram is too big and has Don't Fragment set.</exception>
    public static IReadOnlyList<IPv4Packet> Fragment(IPv4Packet packet, int mtu)
    {
        if (mtu is < IPv4Constants.MinimumMtu or > IPv4Packet.MaximumTotalLength) throw new ArgumentOutOfRangeException(nameof(mtu));
        if (packet.TotalLength > IPv4Packet.MaximumTotalLength) throw new ArgumentException("IPv4 datagram exceeds 65,535 bytes.");
        if (packet.TotalLength <= mtu) return [packet];
        if ((packet.FlagsAndFragmentOffset & IPv4FragmentField.DontFragmentFlag) != 0)
            throw new InvalidOperationException("Packet exceeds MTU with Don't Fragment set.");

        var copiedOptions = IPv4Options.CopiedOptions(packet.Options.Span);
        var fragments = new List<IPv4Packet>();
        for (var payloadOffset = 0; payloadOffset < packet.Payload.Length;)
        {
            var options = payloadOffset == 0 ? packet.Options : copiedOptions;
            var fragment = FragmentAt(packet, payloadOffset, options, mtu);
            fragments.Add(fragment);
            payloadOffset += fragment.Payload.Length;
        }
        return fragments;
    }

    /// <summary>Cuts the fragment that starts <paramref name="payloadOffset"/> bytes into the payload.</summary>
    private static IPv4Packet FragmentAt(IPv4Packet packet, int payloadOffset, ReadOnlyMemory<byte> options, int mtu)
    {
        var length = Math.Min(MaximumFragmentPayload(mtu, options.Length), packet.Payload.Length - payloadOffset);
        var moreFragments = payloadOffset + length < packet.Payload.Length ||
            (packet.FlagsAndFragmentOffset & IPv4FragmentField.MoreFragmentsFlag) != 0;
        var offsetUnits = (packet.FlagsAndFragmentOffset & IPv4FragmentField.FragmentOffsetMask) +
            payloadOffset / IPv4FragmentField.OffsetUnitLength;
        return packet with
        {
            Options = options,
            Payload = packet.Payload.Slice(payloadOffset, length),
            FlagsAndFragmentOffset = (ushort)(offsetUnits | (moreFragments ? IPv4FragmentField.MoreFragmentsFlag : 0))
        };
    }

    /// <summary>Payload that fits after the header, rounded down to whole 8-byte offset units.</summary>
    private static int MaximumFragmentPayload(int mtu, int optionsLength) =>
        (mtu - (IPv4Packet.MinimumHeaderLength + optionsLength)) / IPv4FragmentField.OffsetUnitLength * IPv4FragmentField.OffsetUnitLength;
}
