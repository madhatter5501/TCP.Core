using System.Buffers.Binary;
using System.Net;
using TCP.Checksums;
using TCP.L3.Network.IPv4;

namespace TCP.L3.Network.Icmp;

/// <summary>
/// The datagram an ICMP error is about, as quoted in the error's body: its IPv4 header plus at least the first
/// 8 bytes of its payload (RFC 792).
/// </summary>
/// <remarks>
/// <see cref="IPv4Host"/> uses the quote to decide whether an error concerns a datagram it really sent. The quote
/// must be a well-formed IPv4 header with a valid checksum; only then are its addresses and Identification trusted.
/// </remarks>
/// <param name="Source">Source of the quoted datagram; must be this host for the error to concern us.</param>
/// <param name="Destination">Where the quoted datagram was going.</param>
/// <param name="Protocol">The quoted datagram's upper-layer protocol.</param>
/// <param name="Identification">The quoted datagram's Identification.</param>
internal readonly record struct IcmpErrorQuote(IPAddress Source, IPAddress Destination, byte Protocol, ushort Identification)
{
    private const int MinimumQuotedPayloadLength = 8;
    private const int MinimumQuoteLength = IPv4Packet.MinimumHeaderLength + MinimumQuotedPayloadLength;

    /// <summary>Reads and validates the quote from an ICMP error message's body.</summary>
    /// <returns>False when the quote is too short, not IPv4, or has a bad header checksum.</returns>
    public static bool TryParse(ReadOnlySpan<byte> quote, out IcmpErrorQuote parsed)
    {
        parsed = default;
        if (quote.Length < MinimumQuoteLength) return false;
        var versionAndHeaderLength = quote[IPv4Packet.VersionAndHeaderLengthOffset];
        if (versionAndHeaderLength >> IPv4Packet.VersionFieldShift != IPv4Packet.IPv4Version) return false;

        var headerLength = (versionAndHeaderLength & IPv4Packet.HeaderLengthFieldMask) * IPv4Packet.HeaderLengthUnit;
        if (headerLength < IPv4Packet.MinimumHeaderLength ||
            quote.Length < headerLength + MinimumQuotedPayloadLength ||
            !InternetChecksum.IsValid(quote[..headerLength]))
            return false;

        parsed = new IcmpErrorQuote(
            Source: new IPAddress(quote.Slice(IPv4Packet.SourceAddressOffset, IPv4Packet.IPv4AddressLength)),
            Destination: new IPAddress(quote.Slice(IPv4Packet.DestinationAddressOffset, IPv4Packet.IPv4AddressLength)),
            Protocol: quote[IPv4Packet.ProtocolOffset],
            Identification: BinaryPrimitives.ReadUInt16BigEndian(quote.Slice(IPv4Packet.IdentificationOffset, sizeof(ushort))));
        return true;
    }
}
