using System.Buffers.Binary;
using TCP.L4.Transport.Tcp.Connections;
using static TCP.L4.Transport.Tcp.Segments.TcpWireFormat;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>One SACK block: the half-open sequence range [Start, End) the receiver holds above its cumulative ACK.</summary>
internal readonly record struct SackBlock(SequenceNumber Start, SequenceNumber End)
{
    /// <summary>Whether the block covers all of [start, end).</summary>
    public bool Covers(SequenceNumber start, SequenceNumber end) => Start <= start && end <= End;
}

/// <summary>The two fields of the Timestamps option (RFC 7323 3.2).</summary>
/// <param name="Value">TSval: the sender's timestamp clock when it sent the segment.</param>
/// <param name="EchoReply">TSecr: the most recent TSval the sender received from its peer; valid only with ACK.</param>
internal readonly record struct TcpTimestamp(uint Value, uint EchoReply);

/// <summary>The fixed fields of a TCP-AO option (RFC 5925 2.2) and where its MAC sits in the options area.</summary>
/// <param name="KeyId">The Master Key Tuple the sender used (its SendID).</param>
/// <param name="NextKeyId">The key the sender would like to receive with next (RNextKeyID).</param>
/// <param name="Mac">The message authentication code.</param>
/// <param name="MacOffset">Offset of the MAC within the options area, so a verifier can zero it.</param>
internal readonly record struct TcpAuthenticationField(byte KeyId, byte NextKeyId, byte[] Mac, int MacOffset);

/// <summary>
/// Every option this stack understands, decoded from one segment's options area. Parsing also validates: lengths
/// must match each option's format and a known option may appear only once.
/// </summary>
/// <remarks>
/// Options are how TCP grew after 1981: window scaling, SACK and timestamps (the "long fat network" extensions),
/// Fast Open, user timeout and authentication all ride here. <see cref="TcpConnection"/> negotiates them on the SYN
/// exchange and reads the per-segment ones (timestamps, SACK blocks, authentication) on every arrival.
/// </remarks>
internal sealed class TcpOptions
{
    /// <summary>A timestamp option padded with two NOPs, as it appears on most segments.</summary>
    public const int AlignedTimestampLength = 12;
    /// <summary>An MD5 signature option padded with two NOPs.</summary>
    public const int AlignedMd5Length = 20;
    /// <summary>Largest shift count; larger values are treated as this (RFC 7323 2.3).</summary>
    public const byte MaximumWindowScale = 14;
    public const int MaximumSackBlocks = 4;
    public const int SackBlockLength = 8;
    public const int Md5DigestLength = 16;
    public const int MinimumFastOpenCookieLength = 4;
    public const int MaximumFastOpenCookieLength = 16;
    private const int WindowScaleLength = 3;
    private const int SackPermittedLength = 2;
    private const int TimestampLength = 10;
    private const int UserTimeoutLength = 4;
    private const int Md5Length = OptionHeaderLength + Md5DigestLength;
    private const int AuthenticationHeaderLength = 4;
    private const ushort UserTimeoutGranularityMinutes = 0x8000;
    private const ushort UserTimeoutValueMask = 0x7FFF;

    public static readonly TcpOptions None = new();

    /// <summary>MSS (kind 2, SYN only): the largest segment the sender can receive; null when absent.</summary>
    public ushort? MaximumSegmentSize { get; private set; }

    /// <summary>Window Scale (kind 3, SYN only): the sender's window is shifted left by this many bits, capped at 14 (RFC 7323 2).</summary>
    public byte? WindowScale { get; private set; }

    /// <summary>SACK-Permitted (kind 4, SYN only): the sender can receive selective acknowledgments (RFC 2018).</summary>
    public bool SackPermitted { get; private set; }

    /// <summary>SACK (kind 5): out-of-order ranges the receiver holds, so the sender resends only what is missing; empty when absent.</summary>
    public IReadOnlyList<SackBlock> SackBlocks { get; private set; } = [];

    /// <summary>Timestamps (kind 8): for RTT measurement and protection against wrapped sequence numbers (RFC 7323 3, 5).</summary>
    public TcpTimestamp? Timestamp { get; private set; }

    /// <summary>User Timeout (kind 28): how long the sender will wait for unacknowledged data before giving up (RFC 5482).</summary>
    public TimeSpan? UserTimeout { get; private set; }
    /// <summary>The Fast Open cookie; empty for a cookie request, null when the option is absent.</summary>
    public byte[]? FastOpenCookie { get; private set; }
    /// <summary>TCP Authentication Option (kind 29): a keyed MAC over the segment (RFC 5925); null when absent.</summary>
    public TcpAuthenticationField? Authentication { get; private set; }
    /// <summary>Offset of the MD5 digest within the options area, or null when absent.</summary>
    public int? Md5DigestOffset { get; private set; }

    /// <summary>Decodes and validates an options area.</summary>
    /// <exception cref="ArgumentException">The area is oversized or misaligned, or an option is malformed or repeated.</exception>
    public static TcpOptions Parse(ReadOnlySpan<byte> options)
    {
        if (options.Length > MaximumOptionsLength || options.Length % HeaderWordLength != 0)
            throw new ArgumentException(TcpMessages.InvalidOptionsSize);
        if (options.IsEmpty) return None;
        var parsed = new TcpOptions();
        var seen = new HashSet<TcpOptionKind>();
        var reader = new TcpOptionReader(options);
        while (reader.TryReadNext(out var kind, out var option, out var offset))
        {
            if (!IsKnown(kind)) continue;
            if (!seen.Add(kind))
                throw new ArgumentException(
                    kind == TcpOptionKind.MaximumSegmentSize ? TcpMessages.InvalidMssOption : TcpMessages.InvalidOptionLength);
            parsed.Read(kind, option, offset);
        }
        return parsed;
    }

    /// <summary>Encodes a User Timeout value (RFC 5482 3): seconds when it fits in 15 bits, minutes otherwise.</summary>
    public static ushort EncodeUserTimeout(TimeSpan timeout)
    {
        var seconds = (long)Math.Ceiling(timeout.TotalSeconds);
        if (seconds <= UserTimeoutValueMask) return (ushort)seconds;
        var minutes = Math.Min(UserTimeoutValueMask, (long)Math.Ceiling(timeout.TotalMinutes));
        return (ushort)(UserTimeoutGranularityMinutes | minutes);
    }

    /// <summary>Options this stack decodes; others are skipped by length, as RFC 9293 requires.</summary>
    private static bool IsKnown(TcpOptionKind kind) => kind is TcpOptionKind.MaximumSegmentSize or TcpOptionKind.WindowScale
        or TcpOptionKind.SackPermitted or TcpOptionKind.Sack or TcpOptionKind.Timestamp or TcpOptionKind.Md5Signature
        or TcpOptionKind.UserTimeout or TcpOptionKind.Authentication or TcpOptionKind.FastOpen;

    /// <summary>Checks one option's length against its format and stores its value.</summary>
    private void Read(TcpOptionKind kind, ReadOnlySpan<byte> option, int offset)
    {
        var body = option[OptionHeaderLength..];
        switch (kind)
        {
            case TcpOptionKind.MaximumSegmentSize:
                Require(option.Length == MssOptionLength, TcpMessages.InvalidMssOption);
                MaximumSegmentSize = BinaryPrimitives.ReadUInt16BigEndian(body);
                break;
            case TcpOptionKind.WindowScale:
                Require(option.Length == WindowScaleLength);
                WindowScale = Math.Min(body[0], MaximumWindowScale);
                break;
            case TcpOptionKind.SackPermitted:
                Require(option.Length == SackPermittedLength);
                SackPermitted = true;
                break;
            case TcpOptionKind.Sack:
                Require(body.Length is > 0 and <= MaximumSackBlocks * SackBlockLength && body.Length % SackBlockLength == 0);
                SackBlocks = ReadSackBlocks(body);
                break;
            case TcpOptionKind.Timestamp:
                Require(option.Length == TimestampLength);
                Timestamp = new TcpTimestamp(
                    BinaryPrimitives.ReadUInt32BigEndian(body), BinaryPrimitives.ReadUInt32BigEndian(body[sizeof(uint)..]));
                break;
            case TcpOptionKind.Md5Signature:
                Require(option.Length == Md5Length);
                Md5DigestOffset = offset + OptionHeaderLength;
                break;
            case TcpOptionKind.UserTimeout:
                Require(option.Length == UserTimeoutLength);
                UserTimeout = DecodeUserTimeout(BinaryPrimitives.ReadUInt16BigEndian(body));
                break;
            case TcpOptionKind.Authentication:
                Require(option.Length > AuthenticationHeaderLength);
                Authentication = new TcpAuthenticationField(
                    body[0], body[1], [.. option[AuthenticationHeaderLength..]], offset + AuthenticationHeaderLength);
                break;
            case TcpOptionKind.FastOpen:
                Require(body.IsEmpty || body.Length is >= MinimumFastOpenCookieLength and <= MaximumFastOpenCookieLength);
                FastOpenCookie = [.. body];
                break;
        }
    }

    /// <summary>Decodes the SACK option body: up to four pairs of 32-bit left and right edges.</summary>
    private static SackBlock[] ReadSackBlocks(ReadOnlySpan<byte> body)
    {
        var blocks = new SackBlock[body.Length / SackBlockLength];
        for (var i = 0; i < blocks.Length; i++)
        {
            var block = body[(i * SackBlockLength)..];
            blocks[i] = new SackBlock(
                BinaryPrimitives.ReadUInt32BigEndian(block), BinaryPrimitives.ReadUInt32BigEndian(block[sizeof(uint)..]));
        }
        return blocks;
    }

    /// <summary>The inverse of <see cref="EncodeUserTimeout"/>: the high bit selects minutes over seconds (RFC 5482 3).</summary>
    private static TimeSpan DecodeUserTimeout(ushort value)
    {
        var amount = value & UserTimeoutValueMask;
        return (value & UserTimeoutGranularityMinutes) != 0 ? TimeSpan.FromMinutes(amount) : TimeSpan.FromSeconds(amount);
    }

    /// <summary>Rejects a malformed option with <paramref name="message"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="condition"/> is false.</exception>
    private static void Require(bool condition, string message = TcpMessages.InvalidOptionLength)
    {
        if (!condition) throw new ArgumentException(message);
    }
}
