using System.Buffers.Binary;
using static TCP.L4.Transport.Tcp.Segments.TcpWireFormat;

namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>Builds a word-aligned options area within the 40-byte limit, one option at a time.</summary>
/// <remarks>
/// Each option is preceded by just enough No-Operation bytes that it ends on a 32-bit boundary, the layout common
/// stacks use (for example NOP, NOP, Timestamps). An option that does not fit is refused rather than truncated, so
/// callers add options in priority order and lower-priority ones drop out of a crowded SYN.
/// </remarks>
internal sealed class TcpOptionWriter
{
    private readonly List<byte> _bytes = [];

    /// <summary>Bytes written so far, padding included; always a multiple of 4.</summary>
    public int Length => _bytes.Count;

    /// <summary>Appends <paramref name="option"/> if it fits, padded with leading NOPs to end on a word boundary.</summary>
    /// <returns>The offset of the option within the area, or null when it does not fit in <paramref name="limit"/> bytes.</returns>
    public int? TryAdd(ReadOnlySpan<byte> option, int limit = MaximumOptionsLength)
    {
        var padding = (HeaderWordLength - option.Length % HeaderWordLength) % HeaderWordLength;
        if (_bytes.Count + padding + option.Length > Math.Min(limit, MaximumOptionsLength)) return null;
        for (var i = 0; i < padding; i++) _bytes.Add((byte)TcpOptionKind.NoOperation);
        var offset = _bytes.Count;
        _bytes.AddRange(option);
        return offset;
    }

    /// <summary>The finished options area.</summary>
    public byte[] ToArray() => [.. _bytes];

    /// <summary>Maximum Segment Size (kind 2).</summary>
    public static byte[] MaximumSegmentSize(ushort mss)
    {
        var option = Header(TcpOptionKind.MaximumSegmentSize, MssOptionLength);
        BinaryPrimitives.WriteUInt16BigEndian(option.AsSpan(OptionHeaderLength), mss);
        return option;
    }

    /// <summary>Window Scale (kind 3).</summary>
    public static byte[] WindowScale(byte shift) => [(byte)TcpOptionKind.WindowScale, 3, shift];

    /// <summary>SACK-Permitted (kind 4).</summary>
    public static byte[] SackPermitted() => [(byte)TcpOptionKind.SackPermitted, 2];

    /// <summary>Timestamps (kind 8).</summary>
    public static byte[] Timestamp(TcpTimestamp timestamp)
    {
        var option = Header(TcpOptionKind.Timestamp, 10);
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(OptionHeaderLength), timestamp.Value);
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(OptionHeaderLength + sizeof(uint)), timestamp.EchoReply);
        return option;
    }

    /// <summary>SACK-Permitted followed by Timestamps: 12 bytes with no padding, the usual SYN layout.</summary>
    public static byte[] SackPermittedAndTimestamp(TcpTimestamp timestamp) => [.. SackPermitted(), .. Timestamp(timestamp)];

    /// <summary>SACK (kind 5) carrying <paramref name="blocks"/> in order.</summary>
    public static byte[] Sack(IReadOnlyList<SackBlock> blocks)
    {
        var option = Header(TcpOptionKind.Sack, OptionHeaderLength + blocks.Count * TcpOptions.SackBlockLength);
        for (var i = 0; i < blocks.Count; i++)
        {
            var at = option.AsSpan(OptionHeaderLength + i * TcpOptions.SackBlockLength);
            BinaryPrimitives.WriteUInt32BigEndian(at, blocks[i].Start.Value);
            BinaryPrimitives.WriteUInt32BigEndian(at[sizeof(uint)..], blocks[i].End.Value);
        }
        return option;
    }

    /// <summary>User Timeout (kind 28).</summary>
    public static byte[] UserTimeout(TimeSpan timeout)
    {
        var option = Header(TcpOptionKind.UserTimeout, 4);
        BinaryPrimitives.WriteUInt16BigEndian(option.AsSpan(OptionHeaderLength), TcpOptions.EncodeUserTimeout(timeout));
        return option;
    }

    /// <summary>Fast Open (kind 34): a cookie, or a cookie request when <paramref name="cookie"/> is empty.</summary>
    public static byte[] FastOpen(ReadOnlySpan<byte> cookie) =>
        [(byte)TcpOptionKind.FastOpen, (byte)(OptionHeaderLength + cookie.Length), .. cookie];

    /// <summary>TCP-AO (kind 29) with a zeroed MAC of <paramref name="macLength"/> bytes, to be filled in after signing.</summary>
    public static byte[] Authentication(byte keyId, byte nextKeyId, int macLength)
    {
        var option = Header(TcpOptionKind.Authentication, OptionHeaderLength + 2 + macLength);
        option[OptionHeaderLength] = keyId;
        option[OptionHeaderLength + 1] = nextKeyId;
        return option;
    }

    /// <summary>MD5 Signature (kind 19) with a zeroed digest, to be filled in after signing.</summary>
    public static byte[] Md5Signature() => Header(TcpOptionKind.Md5Signature, OptionHeaderLength + TcpOptions.Md5DigestLength);

    /// <summary>A zeroed option of <paramref name="length"/> bytes with its kind and length octets filled in.</summary>
    private static byte[] Header(TcpOptionKind kind, int length)
    {
        var option = new byte[length];
        option[OptionKindOffset] = (byte)kind;
        option[OptionLengthOffset] = (byte)length;
        return option;
    }
}
