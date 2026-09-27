namespace TCP.L5_7.Application.Http2;

/// <summary>Bytes that violate RFC 9113, with the error code a receiving endpoint would send.</summary>
/// <remarks>
/// A real endpoint answers most of these with GOAWAY (a connection error), and a few with RST_STREAM (a stream
/// error). This decoder only observes, so it reports the code and stops decoding.
/// </remarks>
public sealed class Http2ProtocolException(Http2ErrorCode errorCode, string message) : FormatException(message)
{
    /// <summary>The error code for the GOAWAY or RST_STREAM the violation calls for.</summary>
    public Http2ErrorCode ErrorCode { get; } = errorCode;
}
