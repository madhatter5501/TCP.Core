namespace TCP.L5_7.Application.Http2;

/// <summary>Flag bits in byte 4 of an HTTP/2 frame header. Their meaning depends on the frame type.</summary>
[Flags]
public enum Http2FrameFlags : byte
{
    /// <summary>No flags set.</summary>
    None = 0,
    /// <summary>DATA or HEADERS: the sender's last frame on this stream (half-close).</summary>
    EndStream = 0x01,
    /// <summary>SETTINGS or PING: this frame acknowledges the peer's. Shares its bit with <see cref="EndStream"/>.</summary>
    Ack = 0x01,
    /// <summary>HEADERS, PUSH_PROMISE or CONTINUATION: the header block is complete.</summary>
    EndHeaders = 0x04,
    /// <summary>DATA, HEADERS or PUSH_PROMISE: the payload starts with a pad length byte and ends with padding.</summary>
    Padded = 0x08,
    /// <summary>HEADERS: the payload includes the deprecated priority fields.</summary>
    Priority = 0x20
}
