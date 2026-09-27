using System.Net;
using System.Runtime.InteropServices;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;
using TCP.Stack;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>
/// An HTTP test client built on a second, independent TCP.Core stack. All TcpConnection calls run on the
/// client stack's protocol thread; received bytes are collected for parsing on the test thread.
/// </summary>
internal sealed class VirtualTcpClient
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly EthernetStack _stack;
    private readonly bool _manualRead;
    private readonly Lock _gate = new();
    private readonly List<byte> _received = [];
    private readonly Queue<PendingSend> _sends = new(); // Protocol thread only.
    private readonly TaskCompletionSource _established = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource _progress = NewSignal();
    private TcpConnection _tcp = null!;
    private bool _endOfStream;
    private bool _closed;

    private sealed class PendingSend(byte[] bytes)
    {
        public byte[] Bytes { get; } = bytes;
        public int Offset { get; set; }
        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private VirtualTcpClient(EthernetStack stack, bool manualRead)
    {
        _stack = stack;
        _manualRead = manualRead;
    }

    public ushort LocalPort { get; private set; }
    public string? FailureReason { get; private set; }

    /// <param name="manualRead">Leave received bytes in TCP until <see cref="ReadSomeAsync"/> is called (a slow reader).</param>
    public static async Task<VirtualTcpClient> ConnectAsync(EthernetStack stack, IPAddress server, int port,
        int receiveCapacity = TcpHost.MaximumReceiveCapacity, bool manualRead = false, bool noDelay = false)
    {
        var client = new VirtualTcpClient(stack, manualRead);
        await ProtocolThread.RunAsync(stack, () => client.Open(server, port, receiveCapacity, noDelay));
        await client._established.Task.WaitAsync(DefaultTimeout);
        return client;
    }

    private void Open(IPAddress server, int port, int receiveCapacity, bool noDelay)
    {
        _tcp = _stack.Tcp.Connect(server, (ushort)port, receiveCapacity: receiveCapacity);
        _tcp.NoDelay = noDelay;
        LocalPort = _tcp.LocalPort;
        _tcp.Connected += _ => _established.TrySetResult();
        _tcp.DataAvailable += _ => { if (!_manualRead) Drain(int.MaxValue); };
        _tcp.ReadClosed += _ => Drain(_manualRead ? 0 : int.MaxValue);
        _tcp.SendReady += _ => PumpSends();
        _tcp.StateChanged += (connection, state) =>
        {
            if (state != TcpState.Closed) return;
            lock (_gate) { _closed = true; FailureReason = connection.FailureReason; }
            _established.TrySetException(new IOException(connection.FailureReason ?? "Closed before connecting."));
            foreach (var pending in _sends) pending.Done.TrySetException(new IOException("Connection closed."));
            Signal();
        };
        if (_tcp.State == TcpState.Established) _established.TrySetResult();
    }

    /// <summary>Protocol thread: moves up to <paramref name="maximum"/> bytes out of TCP.</summary>
    private void Drain(int maximum)
    {
        var count = Math.Min(maximum, _tcp.Available);
        var bytes = new byte[count];
        var read = _tcp.Read(bytes);
        lock (_gate)
        {
            _received.AddRange(bytes.AsSpan(0, read));
            if (_tcp.PeerClosed && _tcp.Available == 0) _endOfStream = true;
        }
        Signal();
    }

    private void PumpSends()
    {
        while (_sends.TryPeek(out var pending))
        {
            pending.Offset += _tcp.Send(pending.Bytes.AsSpan(pending.Offset));
            if (pending.Offset < pending.Bytes.Length) return;
            _sends.Dequeue();
            pending.Done.TrySetResult();
        }
    }

    private void Signal()
    {
        TaskCompletionSource previous;
        lock (_gate) { previous = _progress; _progress = NewSignal(); }
        previous.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes once TCP has accepted every byte (not when the server has read them).</summary>
    public async Task SendAsync(ReadOnlyMemory<byte> bytes)
    {
        var pending = new PendingSend(bytes.ToArray());
        await ProtocolThread.RunAsync(_stack, () => { _sends.Enqueue(pending); PumpSends(); });
        await pending.Done.Task.WaitAsync(DefaultTimeout);
    }

    public Task ReadSomeAsync(int maximum) => ProtocolThread.RunAsync(_stack, () => Drain(maximum));

    public async Task<HttpResponse> ReadResponseAsync(TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? DefaultTimeout);
        while (true)
        {
            TaskCompletionSource signal;
            lock (_gate)
            {
                if (HttpResponse.TryParse(CollectionsMarshal.AsSpan(_received), _endOfStream || _closed, out var response, out var consumed))
                {
                    _received.RemoveRange(0, consumed);
                    return response!;
                }
                if (_closed) throw new IOException($"Connection closed before a full response: {FailureReason ?? "graceful close"}");
                signal = _progress;
            }
            await signal.Task.WaitAsync(deadline - DateTime.UtcNow);
        }
    }

    /// <summary>
    /// Stream-style read: copies received bytes, waiting until some arrive. Returns 0 at the server's FIN;
    /// throws if the connection failed with nothing left to read.
    /// </summary>
    public async Task<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            TaskCompletionSource signal;
            lock (_gate)
            {
                if (_received.Count > 0)
                {
                    var count = Math.Min(buffer.Length, _received.Count);
                    CollectionsMarshal.AsSpan(_received)[..count].CopyTo(buffer.Span);
                    _received.RemoveRange(0, count);
                    return count;
                }
                if (_endOfStream || (_closed && FailureReason is null)) return 0;
                if (_closed) throw new IOException($"Connection failed: {FailureReason}");
                signal = _progress;
            }
            await signal.Task.WaitAsync(cancellationToken);
        }
    }

    /// <summary>Waits for the server's FIN (all bytes read) or for the connection to fail.</summary>
    public async Task WaitForEndOfStreamAsync(TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? DefaultTimeout);
        while (true)
        {
            TaskCompletionSource signal;
            lock (_gate)
            {
                if (_endOfStream || _closed) return;
                signal = _progress;
            }
            await signal.Task.WaitAsync(deadline - DateTime.UtcNow);
        }
    }

    public Task<TcpState> GetStateAsync() => ProtocolThread.RunAsync(_stack, () => _tcp.State);
    public Task CloseAsync() => ProtocolThread.RunAsync(_stack, () => _tcp.Close());
    public Task AbortAsync() => ProtocolThread.RunAsync(_stack, () => _tcp.Abort());
}
