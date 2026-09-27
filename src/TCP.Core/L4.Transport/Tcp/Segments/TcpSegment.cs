using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TCP.Checksums;
using TCP.L3.Network.IPv4;
using static TCP.L4.Transport.Tcp.Segments.TcpWireFormat;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>TCP wire codec. Checksum includes the IPv4 or IPv6 pseudo-header. All multibyte values use network order.</summary>
/// <remarks>
/// A segment is TCP's unit of transmission: the header, which holds ports, sequence and acknowledgment numbers,
/// flags, window and options, plus a payload. It travels as the payload of an IPv4 packet. This immutable value is
/// the boundary between bytes and meaning: <see cref="TcpHost"/> calls <see cref="Parse"/> on every arriving
/// IPv4 payload before routing it, and <see cref="Serialize"/> on everything it sends. Invalid input throws
/// <see cref="ArgumentException"/>, which the host treats as "drop silently".
/// </remarks>
/// <param name="SourcePort">Sender's port.</param>
/// <param name="DestinationPort">Receiver's port.</param>
/// <param name="SequenceNumber">Sequence number of the first payload byte, or of the SYN.</param>
/// <param name="AcknowledgmentNumber">Next sequence number the sender expects; meaningful only with <see cref="TcpFlags.Ack"/>.</param>
/// <param name="Flags">Control bits.</param>
/// <param name="Window">Bytes the sender can accept beyond the acknowledgment number.</param>
/// <param name="Payload">Stream data carried.</param>
/// <param name="Options">Raw option bytes, a multiple of 4 and at most 40.</param>
/// <param name="UrgentPointer">Offset from the sequence number to the end of urgent data; meaningful only with <see cref="TcpFlags.Urg"/>.</param>
public readonly record struct TcpSegment(ushort SourcePort, ushort DestinationPort, uint SequenceNumber,
    uint AcknowledgmentNumber, TcpFlags Flags, ushort Window, ReadOnlyMemory<byte> Payload,
    ReadOnlyMemory<byte> Options = default, ushort UrgentPointer = NoUrgentPointer)
{
    /// <summary>Header size in bytes: the 20-byte fixed part plus options.</summary>
    public int HeaderLength => MinimumHeaderLength + Options.Length;

    /// <summary>Sequence space the segment occupies: its payload plus one each for SYN and FIN.</summary>
    public uint SequenceLength => SequenceLengthOf(Flags, Payload.Length);

    /// <summary>Whether any of the given flags is set. Pass a combination such as <c>Syn | Fin</c> to test for either.</summary>
    public bool Has(TcpFlags flag) => (Flags & flag) != TcpFlags.None;

    /// <summary>
    /// The peer's MSS option: the largest payload it can receive in one segment. Null when absent, in which case
    /// RFC 9293 says to assume 536 bytes over IPv4.
    /// </summary>
    /// <exception cref="ArgumentException">The options are malformed.</exception>
    public ushort? MaximumSegmentSize => ReadOptions().MaximumSegmentSize;

    /// <summary>Encodes a 4-byte MSS option (kind 2, length 4, value) to place in <see cref="Options"/> on a SYN.</summary>
    public static byte[] MssOption(ushort mss) => TcpOptionWriter.MaximumSegmentSize(mss);

    /// <summary>Decodes every option this stack understands.</summary>
    /// <exception cref="ArgumentException">The options are malformed.</exception>
    internal TcpOptions ReadOptions() => TcpOptions.Parse(Options.Span);

    /// <summary>
    /// Sequence space occupied by a segment with these flags and this much payload. SYN and FIN each take one
    /// number so that they, like data, can be acknowledged and retransmitted.
    /// </summary>
    internal static uint SequenceLengthOf(TcpFlags flags, int payloadLength)
    {
        var syn = (flags & TcpFlags.Syn) != TcpFlags.None ? ControlSequenceLength : 0u;
        var fin = (flags & TcpFlags.Fin) != TcpFlags.None ? ControlSequenceLength : 0u;
        return (uint)payloadLength + syn + fin;
    }

    /// <summary>
    /// Encodes the segment for the wire, ready to be an IPv4 payload. The addresses are not part of the segment
    /// but are covered by its checksum through the pseudo-header, so a segment misdelivered by IP is detected.
    /// </summary>
    /// <param name="source">Our IPv4 address.</param>
    /// <param name="destination">The peer's IPv4 address.</param>
    /// <exception cref="ArgumentException">Options are malformed, the segment is too large, or the addresses are not one IP family.</exception>
    public byte[] Serialize(IPAddress source, IPAddress destination)
    {
        var bytes = SerializeWithoutChecksum(source);
        var checksum = InternetChecksum.Compute(WithPseudoHeader(source, destination, bytes));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(ChecksumOffset), checksum);
        return bytes;
    }

    /// <summary>
    /// The header and payload with the checksum field zero: the form TCP-AO and MD5 signatures cover
    /// (RFC 5925 5.1, RFC 2385 2.0) before the checksum is filled in.
    /// </summary>
    /// <param name="source">The sender's address, which decides the length limit for its IP family.</param>
    internal byte[] SerializeWithoutChecksum(IPAddress source)
    {
        ReadOptions();
        if (HeaderLength + Payload.Length > MaximumLengthFor(source)) throw new ArgumentException(TcpMessages.SegmentTooLarge);
        var bytes = new byte[HeaderLength + Payload.Length];
        WriteFixedHeader(bytes);
        Options.Span.CopyTo(bytes.AsSpan(MinimumHeaderLength));
        Payload.Span.CopyTo(bytes.AsSpan(HeaderLength));
        return bytes;
    }

    /// <summary>
    /// The pseudo-header that both the checksum and TCP-AO cover (RFC 9293 3.1 for IPv4, RFC 8200 8.1 for IPv6),
    /// followed by <paramref name="segment"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The addresses are not both IPv4 or both IPv6.</exception>
    internal static byte[] WithPseudoHeader(IPAddress source, IPAddress destination, ReadOnlySpan<byte> segment) =>
        PseudoHeader.Prepend(source, destination, (byte)IPv4ProtocolNumber.Tcp, segment);

    /// <summary>
    /// Decodes and validates an IPv4 payload as a TCP segment: length, data offset, checksum against the
    /// pseudo-header, and options, in that order. Payload and options are copied, so the result outlives the buffer.
    /// </summary>
    /// <param name="source">Source address from the IPv4 header.</param>
    /// <param name="destination">Destination address from the IPv4 header.</param>
    /// <param name="bytes">The IPv4 payload.</param>
    /// <exception cref="ArgumentException">The bytes are not a valid TCP segment for these addresses.</exception>
    public static TcpSegment Parse(IPAddress source, IPAddress destination, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < MinimumHeaderLength || bytes.Length > MaximumLengthFor(source))
            throw new ArgumentException(TcpMessages.InvalidSegmentLength);
        var headerLength = (bytes[DataOffsetOffset] >> DataOffsetShift) * HeaderWordLength;
        if (headerLength < MinimumHeaderLength || headerLength > bytes.Length) throw new ArgumentException(TcpMessages.InvalidDataOffset);
        if (!InternetChecksum.IsValid(WithPseudoHeader(source, destination, bytes)))
            throw new ArgumentException(TcpMessages.InvalidChecksum);
        var options = bytes[MinimumHeaderLength..headerLength];
        TcpOptions.Parse(options);
        return new TcpSegment(
            SourcePort: BinaryPrimitives.ReadUInt16BigEndian(bytes[SourcePortOffset..]),
            DestinationPort: BinaryPrimitives.ReadUInt16BigEndian(bytes[DestinationPortOffset..]),
            SequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(bytes[SequenceNumberOffset..]),
            AcknowledgmentNumber: BinaryPrimitives.ReadUInt32BigEndian(bytes[AcknowledgmentNumberOffset..]),
            Flags: (TcpFlags)bytes[FlagsOffset],
            Window: BinaryPrimitives.ReadUInt16BigEndian(bytes[WindowOffset..]),
            Payload: bytes[headerLength..].ToArray(),
            Options: options.ToArray(),
            UrgentPointer: BinaryPrimitives.ReadUInt16BigEndian(bytes[UrgentPointerOffset..]));
    }

    /// <summary>Writes the 20-byte fixed header, leaving the checksum zero.</summary>
    private void WriteFixedHeader(Span<byte> bytes)
    {
        BinaryPrimitives.WriteUInt16BigEndian(bytes[SourcePortOffset..], SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[DestinationPortOffset..], DestinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[SequenceNumberOffset..], SequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[AcknowledgmentNumberOffset..], AcknowledgmentNumber);
        bytes[DataOffsetOffset] = (byte)(HeaderLength / HeaderWordLength << DataOffsetShift);
        bytes[FlagsOffset] = (byte)Flags;
        BinaryPrimitives.WriteUInt16BigEndian(bytes[WindowOffset..], Window);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[UrgentPointerOffset..], UrgentPointer);
    }

    /// <summary>The largest segment an IP datagram of the sender's family can carry without IPv6 jumbograms.</summary>
    private static int MaximumLengthFor(IPAddress source) =>
        source.AddressFamily == AddressFamily.InterNetworkV6 ? MaximumIPv6SegmentLength : MaximumSegmentLength;
}
