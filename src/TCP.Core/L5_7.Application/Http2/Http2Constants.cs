using System.Text;

namespace TCP.L5_7.Application.Http2;

/// <summary>Fixed HTTP/2 wire-format values (RFC 9113).</summary>
public static class Http2Constants
{
    /// <summary>Every HTTP/2 frame starts with a 9-byte header: 24-bit length, type, flags, 31-bit stream identifier.</summary>
    public const int FrameHeaderLength = 9;
    /// <summary>The largest frame payload a peer must accept until it advertises more in SETTINGS_MAX_FRAME_SIZE.</summary>
    public const int DefaultMaxFrameSize = 16_384;
    /// <summary>The largest value SETTINGS_MAX_FRAME_SIZE may take: 2^24 - 1.</summary>
    public const int MaximumFrameSize = (1 << 24) - 1;
    /// <summary>Initial connection and stream flow-control window, in bytes.</summary>
    public const int DefaultInitialWindowSize = 65_535;
    /// <summary>A flow-control window may never exceed 2^31 - 1 bytes.</summary>
    public const int MaximumWindowSize = int.MaxValue;
    /// <summary>Length of one SETTINGS identifier/value pair.</summary>
    public const int SettingLength = 6;
    /// <summary>Length of a PING payload.</summary>
    public const int PingPayloadLength = 8;
    /// <summary>Length of a WINDOW_UPDATE payload.</summary>
    public const int WindowUpdatePayloadLength = 4;
    /// <summary>Length of a RST_STREAM payload.</summary>
    public const int RstStreamPayloadLength = 4;
    /// <summary>Minimum length of a GOAWAY payload: last stream identifier and error code, before optional debug data.</summary>
    public const int GoAwayMinimumPayloadLength = 8;
    /// <summary>Length of the priority fields (exclusive bit, dependency, weight) in PRIORITY and some HEADERS frames.</summary>
    public const int PriorityFieldsLength = 5;
    /// <summary>The high bit of a stream identifier or window increment is reserved and ignored on receipt.</summary>
    public const uint ReservedBitMask = 0x8000_0000;

    /// <summary>
    /// The 24 bytes a client sends before its first frame when it speaks HTTP/2 (RFC 9113 section 3.4).
    /// It looks like an HTTP/1.x request with method PRI so that HTTP/1.1 servers reject it early.
    /// </summary>
    public static ReadOnlySpan<byte> ClientConnectionPreface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    /// <summary>The preface as text, for display.</summary>
    public static string ClientConnectionPrefaceText => Encoding.ASCII.GetString(ClientConnectionPreface);
}
