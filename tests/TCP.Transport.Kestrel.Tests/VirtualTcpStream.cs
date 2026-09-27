using TCP.L5_7.Application.Http2;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>
/// A <see cref="Stream"/> over a <see cref="VirtualTcpClient"/>, returned from SocketsHttpHandler.ConnectCallback
/// so HttpClient speaks HTTP/2 through the client TCP.Core stack. Keeps every byte in both directions, in the
/// order HttpClient wrote or read it, so tests can decode the HTTP/2 frames that crossed TCP.
/// </summary>
internal sealed class VirtualTcpStream(VirtualTcpClient client) : Stream
{
    private readonly Lock _gate = new();
    private readonly List<(bool FromClient, byte[] Bytes)> _chunks = [];
    private int _disposed;

    public VirtualTcpClient Client { get; } = client;

    /// <summary>
    /// Decodes both directions so far into one timeline: client frames when HttpClient wrote them, server frames
    /// when HttpClient read them. A trailing partial frame is left out.
    /// </summary>
    public IReadOnlyList<Http2WireFrame> Frames()
    {
        var fromClient = new Http2FrameReader(isClientToServer: true);
        var fromServer = new Http2FrameReader(isClientToServer: false);
        var frames = new List<Http2WireFrame>();
        lock (_gate)
            foreach (var (isClient, bytes) in _chunks)
                frames.AddRange((isClient ? fromClient : fromServer).Append(bytes).Select(frame => new Http2WireFrame(isClient, frame)));
        return frames;
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await Client.ReadAsync(buffer, cancellationToken);
        lock (_gate) _chunks.Add((false, [.. buffer.Span[..read]]));
        return read;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        lock (_gate) _chunks.Add((true, buffer.ToArray()));
        await Client.SendAsync(buffer).WaitAsync(cancellationToken);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
    public override void Flush() { } // Every write is already handed to TCP.
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>HttpClient disposes the stream when it drops the connection: close TCP gracefully (FIN).</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
            _ = Client.CloseAsync().ContinueWith(_ => { }, TaskScheduler.Default);
        base.Dispose(disposing);
    }
}
