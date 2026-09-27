using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;

namespace TCP.L3.Network.Icmp;

/// <summary>
/// Builds a standalone echo reply ("pong") for an echo request ("ping") datagram, without an <see cref="IPv4Host"/>.
/// </summary>
/// <remarks>
/// Diagnostic tools use this to answer pings from raw captured datagrams. The host's own echo handling, in
/// <see cref="IPv4Host"/>, additionally honors source routes and broadcast rules.
/// </remarks>
public static class IcmpEchoResponder
{
    /// <summary>
    /// Creates the reply datagram: addresses swapped, a fresh TTL, and the request's identifier, sequence number
    /// and data echoed back.
    /// </summary>
    /// <returns>False unless <paramref name="request"/> is a complete, unfragmented, valid ICMP echo request.</returns>
    public static bool TryCreateReply(in IPv4Packet request, out IPv4Packet reply)
    {
        reply = default;
        if (!IsWholeIcmpDatagram(request) ||
            !TryParseIcmp(request, out var icmpRequest) ||
            !icmpRequest.TryCreateEchoReply(out var icmpReply))
            return false;

        reply = new IPv4Packet(
            request.TypeOfService,
            0,
            0,
            IPv4Constants.DefaultTimeToLive,
            (byte)IPv4ProtocolNumber.Icmp,
            request.DestinationAddress,
            request.SourceAddress,
            ReadOnlyMemory<byte>.Empty,
            icmpReply.Serialize());
        return true;
    }

    /// <summary>An ICMP datagram that is not a fragment; a fragment's payload cannot be parsed as a whole message.</summary>
    private static bool IsWholeIcmpDatagram(in IPv4Packet request) =>
        request.Protocol == (byte)IPv4ProtocolNumber.Icmp &&
        (request.FlagsAndFragmentOffset & IPv4FragmentField.ReassemblyMask) == 0;

    /// <summary>Decodes the ICMP message, treating a malformed one or a bad checksum as "not an echo request".</summary>
    private static bool TryParseIcmp(in IPv4Packet request, out IcmpPacket message)
    {
        try
        {
            message = IcmpPacket.Parse(request.Payload.Span);
            return true;
        }
        catch (ArgumentException)
        {
            message = default;
            return false;
        }
    }
}
