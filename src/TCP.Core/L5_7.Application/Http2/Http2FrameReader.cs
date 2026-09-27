using System.Runtime.InteropServices;

namespace TCP.L5_7.Application.Http2;

/// <summary>
/// Decodes one direction of an HTTP/2 connection from bytes as TCP delivers them, in chunks of any size.
/// </summary>
/// <remarks>
/// TCP preserves byte order but not message boundaries, so this buffers partial frames until the 9-byte
/// header and the whole payload have arrived. The client-to-server direction starts with the 24-byte
/// connection preface; the server's first frame must be SETTINGS (RFC 9113 section 3.4). The reader also
/// enforces that a header block split across frames continues with CONTINUATION on the same stream and
/// nothing else (section 6.10). HPACK (RFC 7541) is not decoded: header blocks stay opaque bytes.
/// </remarks>
public sealed class Http2FrameReader
{
    private readonly List<byte> _buffer = [];
    private readonly bool _isClientToServer;
    private int _prefaceBytesMatched;
    private bool _sawFirstFrame;
    private int _openHeaderBlockStream; // Stream whose header block awaits END_HEADERS; 0 when none.

    /// <param name="isClientToServer">True for bytes the client sends, which begin with the connection preface.</param>
    /// <param name="maxFrameSize">The receiving endpoint's SETTINGS_MAX_FRAME_SIZE.</param>
    public Http2FrameReader(bool isClientToServer, int maxFrameSize = Http2Constants.DefaultMaxFrameSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFrameSize, Http2Constants.DefaultMaxFrameSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxFrameSize, Http2Constants.MaximumFrameSize);
        _isClientToServer = isClientToServer;
        MaxFrameSize = maxFrameSize;
    }

    /// <summary>
    /// The largest payload accepted. Raise it when the receiving endpoint advertises a larger
    /// SETTINGS_MAX_FRAME_SIZE (which the reader of the opposite direction sees).
    /// </summary>
    public int MaxFrameSize { get; set; }

    /// <summary>True once the whole client preface has been matched, or always for the server direction.</summary>
    public bool PrefaceComplete => !_isClientToServer || _prefaceBytesMatched == Http2Constants.ClientConnectionPreface.Length;

    /// <summary>Bytes received but not yet part of a complete frame.</summary>
    public int BufferedBytes => _buffer.Count;

    /// <summary>Adds received bytes and returns every frame they complete, in order.</summary>
    /// <exception cref="Http2ProtocolException">
    /// A bad preface or malformed frame. Decoding cannot continue, as it could not on a real connection.
    /// </exception>
    public IReadOnlyList<Http2Frame> Append(ReadOnlySpan<byte> bytes)
    {
        bytes = MatchPreface(bytes);
        _buffer.AddRange(bytes);
        var frames = new List<Http2Frame>();
        var offset = 0;
        var buffered = CollectionsMarshal.AsSpan(_buffer);
        while (Http2Frame.TryParse(buffered[offset..], MaxFrameSize, out var frame, out var consumed))
        {
            CheckSequence(frame);
            frames.Add(frame);
            offset += consumed;
        }
        _buffer.RemoveRange(0, offset);
        return frames;
    }

    private ReadOnlySpan<byte> MatchPreface(ReadOnlySpan<byte> bytes)
    {
        if (PrefaceComplete) return bytes;
        var preface = Http2Constants.ClientConnectionPreface;
        var count = Math.Min(bytes.Length, preface.Length - _prefaceBytesMatched);
        if (!bytes[..count].SequenceEqual(preface.Slice(_prefaceBytesMatched, count)))
            throw new Http2ProtocolException(Http2ErrorCode.ProtocolError,
                "The client did not start with the HTTP/2 connection preface; this may be HTTP/1.1.");
        _prefaceBytesMatched += count;
        return bytes[count..];
    }

    private void CheckSequence(Http2Frame frame)
    {
        if (!_sawFirstFrame)
        {
            _sawFirstFrame = true;
            if (frame.Type != Http2FrameType.Settings || frame.HasFlag(Http2FrameFlags.Ack))
                throw new Http2ProtocolException(Http2ErrorCode.ProtocolError,
                    $"The first frame after the preface must be SETTINGS, not {frame}.");
        }
        if (_openHeaderBlockStream != 0)
        {
            if (frame.Type != Http2FrameType.Continuation || frame.StreamId != _openHeaderBlockStream)
                throw new Http2ProtocolException(Http2ErrorCode.ProtocolError,
                    $"Expected CONTINUATION on stream {_openHeaderBlockStream}, not {frame}.");
        }
        else if (frame.Type == Http2FrameType.Continuation)
        {
            throw new Http2ProtocolException(Http2ErrorCode.ProtocolError, "CONTINUATION without an open header block.");
        }
        if (frame.Type is Http2FrameType.Headers or Http2FrameType.PushPromise or Http2FrameType.Continuation)
            _openHeaderBlockStream = frame.HasFlag(Http2FrameFlags.EndHeaders) ? 0 : frame.StreamId;
    }
}
