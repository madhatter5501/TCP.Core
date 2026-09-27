using System.Buffers.Binary;

namespace TCP.L5_7.Application.Http2;

/// <summary>One decoded HTTP/2 frame (RFC 9113 section 4): the 9-byte header and its payload.</summary>
/// <remarks>
/// HTTP/2 turns one TCP byte stream into many independent request/response streams. Every frame names the
/// stream it belongs to; stream 0 carries connection-level control (SETTINGS, PING, GOAWAY, connection
/// WINDOW_UPDATE). Client-initiated streams use odd identifiers, so frames for streams 1, 3 and 5 can be
/// interleaved on the wire and reassembled by identifier. Frames do not align with TCP segments: one segment
/// can hold several frames, and one frame can span several segments. Use <see cref="Http2FrameReader"/> to
/// decode a captured byte stream.
/// </remarks>
/// <param name="Type">The frame type. Unknown types are kept and must be ignored by receivers.</param>
/// <param name="Flags">Type-specific flags.</param>
/// <param name="StreamId">The 31-bit stream identifier, with the reserved bit cleared. 0 means the connection.</param>
/// <param name="Payload">The frame payload, including any padding.</param>
public readonly record struct Http2Frame(Http2FrameType Type, Http2FrameFlags Flags, int StreamId, ReadOnlyMemory<byte> Payload)
{
    private const int LengthOffset = 0;
    private const int TypeOffset = 3;
    private const int FlagsOffset = 4;
    private const int StreamIdOffset = 5;
    private const int PadLengthFieldLength = 1;
    private const int ErrorCodeLength = 4;
    private const int GoAwayErrorCodeOffset = 4;

    /// <summary>Length of the payload as written in the frame header.</summary>
    public int Length => Payload.Length;

    /// <summary>Whether a flag is set. Flags are meaningful only for the frame types that define them.</summary>
    public bool HasFlag(Http2FrameFlags flag) => (Flags & flag) == flag;

    /// <summary>
    /// Bytes this frame consumes from the flow-control windows. Only DATA is flow controlled, and its padding
    /// counts too (RFC 9113 section 6.1).
    /// </summary>
    public int FlowControlledLength => Type == Http2FrameType.Data ? Payload.Length : 0;

    /// <summary>DATA: the application bytes, without the pad length byte and padding.</summary>
    public ReadOnlyMemory<byte> Data => Type == Http2FrameType.Data
        ? Unpadded()
        : throw new InvalidOperationException("Only DATA frames carry data.");

    /// <summary>HEADERS, PUSH_PROMISE or CONTINUATION: the HPACK-encoded header block fragment.</summary>
    public ReadOnlyMemory<byte> HeaderBlockFragment => Type switch
    {
        Http2FrameType.Headers => Unpadded()[(HasFlag(Http2FrameFlags.Priority) ? Http2Constants.PriorityFieldsLength : 0)..],
        Http2FrameType.PushPromise => Unpadded()[sizeof(uint)..],
        Http2FrameType.Continuation => Payload,
        _ => throw new InvalidOperationException("Only HEADERS, PUSH_PROMISE and CONTINUATION carry a header block.")
    };

    /// <summary>WINDOW_UPDATE: the credit granted, 1 to 2^31 - 1 bytes.</summary>
    public int WindowSizeIncrement => Type == Http2FrameType.WindowUpdate
        ? (int)(BinaryPrimitives.ReadUInt32BigEndian(Payload.Span) & ~Http2Constants.ReservedBitMask)
        : throw new InvalidOperationException("Only WINDOW_UPDATE frames carry a window increment.");

    /// <summary>RST_STREAM or GOAWAY: why the stream or connection is ending.</summary>
    public Http2ErrorCode ErrorCode => Type switch
    {
        Http2FrameType.RstStream => (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(Payload.Span),
        Http2FrameType.GoAway => (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(Payload.Span[GoAwayErrorCodeOffset..]),
        _ => throw new InvalidOperationException("Only RST_STREAM and GOAWAY frames carry an error code.")
    };

    /// <summary>GOAWAY: the highest stream the sender may have processed. Higher streams can be retried elsewhere.</summary>
    public int LastStreamId => Type == Http2FrameType.GoAway
        ? (int)(BinaryPrimitives.ReadUInt32BigEndian(Payload.Span) & ~Http2Constants.ReservedBitMask)
        : throw new InvalidOperationException("Only GOAWAY frames carry a last stream identifier.");

    /// <summary>SETTINGS: the parameters in the order sent. An acknowledgment carries none.</summary>
    public IReadOnlyList<Http2Setting> Settings
    {
        get
        {
            if (Type != Http2FrameType.Settings) throw new InvalidOperationException("Only SETTINGS frames carry settings.");
            var settings = new List<Http2Setting>(Payload.Length / Http2Constants.SettingLength);
            for (var offset = 0; offset < Payload.Length; offset += Http2Constants.SettingLength)
            {
                var entry = Payload.Span.Slice(offset, Http2Constants.SettingLength);
                settings.Add(new Http2Setting((Http2SettingId)BinaryPrimitives.ReadUInt16BigEndian(entry),
                    BinaryPrimitives.ReadUInt32BigEndian(entry[sizeof(ushort)..])));
            }
            return settings;
        }
    }

    /// <summary>
    /// Decodes one frame from the start of <paramref name="bytes"/>. Returns false if more bytes are needed.
    /// </summary>
    /// <param name="maxFrameSize">The receiver's advertised SETTINGS_MAX_FRAME_SIZE.</param>
    /// <param name="consumed">Header plus payload length when a frame was decoded; otherwise 0.</param>
    /// <exception cref="Http2ProtocolException">The frame is too large or malformed for its type.</exception>
    public static bool TryParse(ReadOnlySpan<byte> bytes, int maxFrameSize, out Http2Frame frame, out int consumed)
    {
        frame = default;
        consumed = 0;
        if (bytes.Length < Http2Constants.FrameHeaderLength) return false;
        var length = (bytes[LengthOffset] << 16) | (bytes[LengthOffset + 1] << 8) | bytes[LengthOffset + 2];
        if (length > maxFrameSize)
            throw new Http2ProtocolException(Http2ErrorCode.FrameSizeError,
                $"A {length}-byte frame payload exceeds SETTINGS_MAX_FRAME_SIZE ({maxFrameSize}).");
        if (bytes.Length < Http2Constants.FrameHeaderLength + length) return false;
        var streamId = (int)(BinaryPrimitives.ReadUInt32BigEndian(bytes[StreamIdOffset..]) & ~Http2Constants.ReservedBitMask);
        frame = new Http2Frame((Http2FrameType)bytes[TypeOffset], (Http2FrameFlags)bytes[FlagsOffset], streamId,
            bytes.Slice(Http2Constants.FrameHeaderLength, length).ToArray());
        frame.Validate();
        consumed = Http2Constants.FrameHeaderLength + length;
        return true;
    }

    /// <summary>Encodes the 9-byte header followed by the payload.</summary>
    public byte[] Serialize()
    {
        var bytes = new byte[Http2Constants.FrameHeaderLength + Payload.Length];
        bytes[LengthOffset] = (byte)(Payload.Length >> 16);
        bytes[LengthOffset + 1] = (byte)(Payload.Length >> 8);
        bytes[LengthOffset + 2] = (byte)Payload.Length;
        bytes[TypeOffset] = (byte)Type;
        bytes[FlagsOffset] = (byte)Flags;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(StreamIdOffset), (uint)StreamId);
        Payload.Span.CopyTo(bytes.AsSpan(Http2Constants.FrameHeaderLength));
        return bytes;
    }

    /// <summary>A one-line label such as <c>DATA stream 3, 16384 B [END_STREAM]</c>.</summary>
    public override string ToString()
    {
        var name = Type switch
        {
            Http2FrameType.RstStream => "RST_STREAM",
            Http2FrameType.PushPromise => "PUSH_PROMISE",
            Http2FrameType.GoAway => "GOAWAY",
            Http2FrameType.WindowUpdate => "WINDOW_UPDATE",
            _ when Enum.IsDefined(Type) => Type.ToString().ToUpperInvariant(),
            _ => $"UNKNOWN(0x{(byte)Type:x2})"
        };
        var detail = Type switch
        {
            Http2FrameType.Data => $"{Data.Length} B",
            Http2FrameType.Headers or Http2FrameType.Continuation => $"{HeaderBlockFragment.Length} B header block",
            Http2FrameType.Settings when HasFlag(Http2FrameFlags.Ack) => "ACK",
            Http2FrameType.Settings => string.Join(", ", Settings),
            Http2FrameType.WindowUpdate => $"+{WindowSizeIncrement} B",
            Http2FrameType.RstStream => ErrorCode.ToString(),
            Http2FrameType.GoAway => $"last stream {LastStreamId}, {ErrorCode}",
            Http2FrameType.Ping => HasFlag(Http2FrameFlags.Ack) ? "ACK" : "",
            _ => $"{Length} B"
        };
        var flags = FlagNames();
        return $"{name} {(StreamId == 0 ? "connection" : $"stream {StreamId}")}{(detail.Length > 0 ? $", {detail}" : "")}{(flags.Length > 0 ? $" [{flags}]" : "")}";
    }

    private string FlagNames()
    {
        var names = new List<string>();
        if (HasFlag(Http2FrameFlags.EndStream) && Type is Http2FrameType.Data or Http2FrameType.Headers) names.Add("END_STREAM");
        if (HasFlag(Http2FrameFlags.EndHeaders) && Type is Http2FrameType.Headers or Http2FrameType.PushPromise or Http2FrameType.Continuation) names.Add("END_HEADERS");
        if (HasFlag(Http2FrameFlags.Padded) && Type is Http2FrameType.Data or Http2FrameType.Headers or Http2FrameType.PushPromise) names.Add("PADDED");
        if (HasFlag(Http2FrameFlags.Priority) && Type == Http2FrameType.Headers) names.Add("PRIORITY");
        return string.Join(" ", names);
    }

    /// <summary>The payload without the pad length byte and trailing padding, for types that allow PADDED.</summary>
    private ReadOnlyMemory<byte> Unpadded()
    {
        if (!HasFlag(Http2FrameFlags.Padded)) return Payload;
        var padLength = Payload.Span[0];
        return Payload[PadLengthFieldLength..(Payload.Length - padLength)];
    }

    /// <summary>The size and stream rules of RFC 9113 section 6 that can be checked from one frame.</summary>
    private void Validate()
    {
        switch (Type)
        {
            case Http2FrameType.Data:
            case Http2FrameType.Headers:
            case Http2FrameType.PushPromise:
                RequireStream();
                var fixedLength = Type switch
                {
                    Http2FrameType.Headers when HasFlag(Http2FrameFlags.Priority) => Http2Constants.PriorityFieldsLength,
                    Http2FrameType.PushPromise => sizeof(uint),
                    _ => 0
                };
                var padding = HasFlag(Http2FrameFlags.Padded)
                    ? (Payload.Length == 0 ? throw Protocol(Http2ErrorCode.FrameSizeError, "is PADDED but has no pad length byte") : PadLengthFieldLength + Payload.Span[0])
                    : 0;
                if (padding + fixedLength > Payload.Length)
                    throw Protocol(Http2ErrorCode.ProtocolError, "has more padding than payload");
                break;
            case Http2FrameType.Priority:
                RequireStream();
                RequireLength(Http2Constants.PriorityFieldsLength);
                break;
            case Http2FrameType.RstStream:
                RequireStream();
                RequireLength(Http2Constants.RstStreamPayloadLength);
                break;
            case Http2FrameType.Settings:
                RequireConnection();
                if (HasFlag(Http2FrameFlags.Ack) && Payload.Length != 0)
                    throw Protocol(Http2ErrorCode.FrameSizeError, "acknowledges settings but has a payload");
                if (Payload.Length % Http2Constants.SettingLength != 0)
                    throw Protocol(Http2ErrorCode.FrameSizeError, $"length is not a multiple of {Http2Constants.SettingLength}");
                break;
            case Http2FrameType.Ping:
                RequireConnection();
                RequireLength(Http2Constants.PingPayloadLength);
                break;
            case Http2FrameType.GoAway:
                RequireConnection();
                if (Payload.Length < Http2Constants.GoAwayMinimumPayloadLength)
                    throw Protocol(Http2ErrorCode.FrameSizeError, $"is shorter than {Http2Constants.GoAwayMinimumPayloadLength} bytes");
                break;
            case Http2FrameType.WindowUpdate:
                RequireLength(Http2Constants.WindowUpdatePayloadLength);
                if (WindowSizeIncrement == 0)
                    throw Protocol(Http2ErrorCode.ProtocolError, "grants a zero increment");
                break;
            case Http2FrameType.Continuation:
                RequireStream();
                break;
        }
    }

    private void RequireStream()
    {
        if (StreamId == 0) throw Protocol(Http2ErrorCode.ProtocolError, "must belong to a stream, not stream 0");
    }

    private void RequireConnection()
    {
        if (StreamId != 0) throw Protocol(Http2ErrorCode.ProtocolError, "must be sent on stream 0");
    }

    private void RequireLength(int expected)
    {
        if (Payload.Length != expected) throw Protocol(Http2ErrorCode.FrameSizeError, $"must have a {expected}-byte payload, not {Payload.Length}");
    }

    private Http2ProtocolException Protocol(Http2ErrorCode code, string problem) =>
        new(code, $"{Type} frame on stream {StreamId} {problem}.");
}
