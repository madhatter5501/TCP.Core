using System.Buffers.Binary;
using TCP.Checksums;

namespace TCP.L3.Network.Icmp;

/// <summary>An ICMPv4 message, including its checksum and message body.</summary>
/// <remarks>
/// ICMP (RFC 792) is IP's control channel, carried as IP protocol 1. It covers echo request and reply (ping),
/// and error reports such as "destination unreachable" or "fragmentation needed" that quote the datagram that
/// caused them. Every message has an 8-byte header: type, code, checksum, and a 4-byte field whose meaning
/// depends on the type. The header is followed by a type-specific body.
/// </remarks>
/// <param name="Type">Message type; see <see cref="IcmpMessageType"/>.</param>
/// <param name="Code">Subtype within the type, such as which kind of Destination Unreachable.</param>
/// <param name="RestOfHeader">
/// The type-specific second header word: identifier and sequence for echo, the next-hop MTU for fragmentation
/// needed, the gateway for a redirect, the pointer for a parameter problem.
/// </param>
/// <param name="Payload">The body: echo data, or the quoted datagram for errors.</param>
public readonly record struct IcmpPacket(
    byte Type,
    byte Code,
    uint RestOfHeader,
    ReadOnlyMemory<byte> Payload)
{
    /// <summary>Length of the fixed ICMP header.</summary>
    public const int HeaderLength = 8;
    /// <summary>Type byte of an echo reply.</summary>
    public const byte EchoReplyType = (byte)IcmpMessageType.EchoReply;
    /// <summary>Type byte of an echo request.</summary>
    public const byte EchoRequestType = (byte)IcmpMessageType.EchoRequest;
    /// <summary>The only defined code for echo messages.</summary>
    public const byte EchoCode = 0;
    private const int TypeOffset = 0;
    private const int CodeOffset = 1;
    private const int ChecksumOffset = 2;
    private const int RestOfHeaderOffset = 4;
    private const int IdentifierShift = 16;

    /// <summary>For echo messages: chosen by the sender to match replies to its requests, typically per process.</summary>
    public ushort Identifier => (ushort)(RestOfHeader >> IdentifierShift);

    /// <summary>For echo messages: incremented by the sender for each request.</summary>
    public ushort SequenceNumber => (ushort)RestOfHeader;

    /// <summary>Decodes an ICMP message from an IPv4 payload, verifying its checksum over the whole message.</summary>
    /// <exception cref="ArgumentException">Shorter than the header, or the checksum is wrong.</exception>
    public static IcmpPacket Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderLength)
        {
            throw new ArgumentException("An ICMPv4 message must contain at least an 8-byte header.", nameof(bytes));
        }

        if (!InternetChecksum.IsValid(bytes))
        {
            throw new ArgumentException("The ICMPv4 checksum is invalid.", nameof(bytes));
        }

        return new IcmpPacket(
            bytes[TypeOffset],
            bytes[CodeOffset],
            BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(RestOfHeaderOffset, sizeof(uint))),
            bytes[HeaderLength..].ToArray());
    }

    /// <summary>Encodes the message and computes its checksum, ready to be an IPv4 payload.</summary>
    public byte[] Serialize()
    {
        var bytes = new byte[HeaderLength + Payload.Length];
        bytes[TypeOffset] = Type;
        bytes[CodeOffset] = Code;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(RestOfHeaderOffset), RestOfHeader);
        Payload.Span.CopyTo(bytes.AsSpan(HeaderLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            bytes.AsSpan(ChecksumOffset),
            InternetChecksum.Compute(bytes));
        return bytes;
    }

    /// <summary>Builds a ping: an echo request carrying <paramref name="payload"/>, which the target echoes back.</summary>
    public static IcmpPacket CreateEchoRequest(
        ushort identifier,
        ushort sequenceNumber,
        ReadOnlyMemory<byte> payload) =>
        new(EchoRequestType, EchoCode, ((uint)identifier << IdentifierShift) | sequenceNumber, payload);

    /// <summary>Turns an echo request into its reply: the same message with the type changed (RFC 792).</summary>
    /// <returns>False when this is not a valid echo request.</returns>
    public bool TryCreateEchoReply(out IcmpPacket reply)
    {
        if (Type != EchoRequestType || Code != EchoCode)
        {
            reply = default;
            return false;
        }

        reply = this with { Type = EchoReplyType };
        return true;
    }
}
