namespace TCP.L5_7.Application.Http2;

/// <summary>Error codes carried by RST_STREAM and GOAWAY (RFC 9113 section 7).</summary>
public enum Http2ErrorCode : uint
{
    /// <summary>Not an error; for example a graceful GOAWAY.</summary>
    NoError = 0x0,
    /// <summary>A generic protocol violation.</summary>
    ProtocolError = 0x1,
    /// <summary>The endpoint hit an unexpected internal error.</summary>
    InternalError = 0x2,
    /// <summary>The peer sent more data than the flow-control window allowed.</summary>
    FlowControlError = 0x3,
    /// <summary>A SETTINGS frame was not acknowledged in time.</summary>
    SettingsTimeout = 0x4,
    /// <summary>A frame arrived on a stream that was already half-closed.</summary>
    StreamClosed = 0x5,
    /// <summary>A frame had an invalid size.</summary>
    FrameSizeError = 0x6,
    /// <summary>The stream was refused before any application processing; safe to retry.</summary>
    RefusedStream = 0x7,
    /// <summary>The stream is no longer needed.</summary>
    Cancel = 0x8,
    /// <summary>The HPACK compression context could not be maintained.</summary>
    CompressionError = 0x9,
    /// <summary>A CONNECT tunnel's TCP connection was reset or closed abnormally.</summary>
    ConnectError = 0xa,
    /// <summary>The peer appears to be generating excessive load.</summary>
    EnhanceYourCalm = 0xb,
    /// <summary>The transport does not meet minimum security requirements.</summary>
    InadequateSecurity = 0xc,
    /// <summary>The endpoint requires HTTP/1.1 instead of HTTP/2.</summary>
    Http11Required = 0xd
}
