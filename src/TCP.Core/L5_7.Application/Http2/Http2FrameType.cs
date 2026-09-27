namespace TCP.L5_7.Application.Http2;

/// <summary>HTTP/2 frame types (RFC 9113 section 6), carried in byte 3 of the frame header.</summary>
/// <remarks>
/// Endpoints must ignore frame types they do not understand (RFC 9113 section 4.1), so a decoded frame may
/// carry a value outside this enum.
/// </remarks>
public enum Http2FrameType : byte
{
    /// <summary>Request or response body bytes for one stream; subject to flow control.</summary>
    Data = 0x0,
    /// <summary>Opens a stream and carries an HPACK-compressed header block (or trailers).</summary>
    Headers = 0x1,
    /// <summary>Deprecated stream prioritization (RFC 9113 section 5.3.2). Parsed, never acted on.</summary>
    Priority = 0x2,
    /// <summary>Immediately terminates one stream with an error code; the connection stays open.</summary>
    RstStream = 0x3,
    /// <summary>Connection configuration, such as the initial flow-control window. Always on stream 0.</summary>
    Settings = 0x4,
    /// <summary>Server push (reserves a stream). Disabled by most clients.</summary>
    PushPromise = 0x5,
    /// <summary>A liveness and round-trip probe; the peer echoes the 8 bytes with ACK set.</summary>
    Ping = 0x6,
    /// <summary>Graceful or error shutdown of the whole connection, naming the last stream processed.</summary>
    GoAway = 0x7,
    /// <summary>Grants the sender more flow-control credit for one stream, or for the connection on stream 0.</summary>
    WindowUpdate = 0x8,
    /// <summary>Continues a header block that did not fit in one HEADERS or PUSH_PROMISE frame.</summary>
    Continuation = 0x9
}
