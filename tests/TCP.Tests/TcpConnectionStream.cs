using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.Tests;

/// <summary>
/// Presents a <see cref="TcpConnection"/> as a thread-safe <see cref="Stream"/>, so .NET's SslStream can run over
/// the in-memory stack.
/// </summary>
/// <remarks>
/// A TcpConnection may only be touched on its protocol thread, while SslStream reads and writes from thread-pool
/// threads (and on macOS, Network.framework's own queues). The two sides meet in two locked queues:
/// <see cref="Service"/>, called on the protocol thread, moves received bytes into the inbound queue and queued
/// writes into TCP; the Stream methods only touch the queues and signal <c>activity</c> so the protocol loop wakes.
/// </remarks>
internal sealed class TcpConnectionStream : Stream
{
    private readonly TcpConnection _tcp;
    private readonly SemaphoreSlim _activity;
    private readonly Lock _gate = new();
    private readonly Queue<byte[]> _inbound = new();
    private readonly Queue<byte[]> _outbound = new();
    private int _inboundOffset;
    private int _outboundOffset;
    private bool _endOfStream;
    private bool _closeRequested;
    private bool _closed;
    private TaskCompletionSource? _readWaiter;

    /// <summary>Wraps <paramref name="tcp"/>; <paramref name="activity"/> is released whenever the Stream side has work for <see cref="Service"/>.</summary>
    public TcpConnectionStream(TcpConnection tcp, SemaphoreSlim activity)
    {
        _tcp = tcp;
        _activity = activity;
        tcp.DataAvailable += _ => Service();
        tcp.ReadClosed += _ => Service();
        tcp.SendReady += _ => Service();
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    /// <summary>Protocol thread: moves bytes between TCP and the queues. Returns whether anything moved.</summary>
    public bool Service()
    {
        var progress = false;
        TaskCompletionSource? wake = null;
        lock (_gate)
        {
            while (_tcp.Available > 0)
            {
                var bytes = new byte[_tcp.Available];
                _tcp.Read(bytes);
                _inbound.Enqueue(bytes);
                progress = true;
            }
            if (!_endOfStream && (_tcp.PeerClosed || _tcp.State == TcpState.Closed))
            {
                _endOfStream = true;
                progress = true;
            }
            if (progress && _readWaiter is not null) (wake, _readWaiter) = (_readWaiter, null);
            while (_outbound.TryPeek(out var head) && _tcp.State is TcpState.Established or TcpState.CloseWait)
            {
                var sent = _tcp.Send(head.AsSpan(_outboundOffset));
                if (sent == 0) break;
                progress = true;
                _outboundOffset += sent;
                if (_outboundOffset < head.Length) break;
                _outbound.Dequeue();
                _outboundOffset = 0;
            }
            if (_closeRequested && _outbound.Count == 0 && !_closed)
            {
                _closed = true;
                _tcp.Close();
                progress = true;
            }
        }
        wake?.TrySetResult();
        return progress;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            Task wait;
            lock (_gate)
            {
                if (_inbound.TryPeek(out var head))
                {
                    var count = Math.Min(buffer.Length, head.Length - _inboundOffset);
                    head.AsMemory(_inboundOffset, count).CopyTo(buffer);
                    _inboundOffset += count;
                    if (_inboundOffset == head.Length) { _inbound.Dequeue(); _inboundOffset = 0; }
                    return count;
                }
                if (_endOfStream) return 0;
                _readWaiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _readWaiter.Task;
            }
            _activity.Release();
            await wait.WaitAsync(cancellationToken);
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, default).GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        lock (_gate) _outbound.Enqueue(buffer.ToArray());
        _activity.Release();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        Write(buffer.AsSpan(offset, count));
        return Task.CompletedTask;
    }

    public override void Flush() { }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Asks the protocol thread to close TCP's sending side once queued writes are out.</summary>
    protected override void Dispose(bool disposing)
    {
        lock (_gate) _closeRequested = true;
        _activity.Release();
        base.Dispose(disposing);
    }
}
