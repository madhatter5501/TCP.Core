using System.IO.Pipelines;
using System.Net;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;

namespace TCP.Transport.Kestrel;

/// <summary>
/// Maps one TCP.Core byte stream to Kestrel's duplex pipe. TcpConnection is only touched on the protocol
/// thread; each pipe end is owned by exactly one pump task. Graceful close sends FIN and leaves FIN-WAIT
/// and TIME-WAIT to <see cref="TcpHost"/>; only abort, failure or undrained output resets the connection.
/// </summary>
internal sealed class TcpCoreConnection : ConnectionContext
{
    // Kestrel-side pipes: writers pause above the first threshold and resume below the second.
    private const int PipePauseThresholdBytes = 65_536;
    private const int PipeResumeThresholdBytes = 32_768;
    // Bytes read out of TCP but not yet written to the input pipe. When full, the protocol thread stops
    // reading, TCP's receive buffer fills and its advertised window closes: backpressure reaches the peer.
    private const int InputQueueLimitBytes = 65_536;
    private const int InputChunkBytes = 16_384;
    private const int OutputChunkBytes = 16_384;
    private static readonly TimeSpan ResumeRetryDelay = TimeSpan.FromMilliseconds(10);
    // After Kestrel disposes, how long queued response bytes may take to enter TCP's send buffer.
    private static readonly TimeSpan OutputDrainTimeout = TimeSpan.FromSeconds(5);
    private static readonly PipeOptions TransportPipeOptions = new(
        pauseWriterThreshold: PipePauseThresholdBytes,
        resumeWriterThreshold: PipeResumeThresholdBytes,
        readerScheduler: PipeScheduler.ThreadPool,
        writerScheduler: PipeScheduler.ThreadPool,
        useSynchronizationContext: false);

    private readonly TcpCoreHostService _host;
    private readonly TcpConnection _tcp;
    private readonly Pipe _inbound = new(TransportPipeOptions);   // TCP -> Kestrel
    private readonly Pipe _outbound = new(TransportPipeOptions);  // Kestrel -> TCP
    private readonly Channel<byte[]> _input = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly Queue<PendingWrite> _pendingWrites = new();
    private readonly Lock _writeGate = new();
    private readonly CancellationTokenSource _pumpAbort = new();
    private readonly CancellationTokenSource _closed = new();
    private readonly Task _inputPump;
    private readonly Task _outputPump;
    private int _queuedInputBytes;
    private int _detached;
    private volatile bool _outputClosedGracefully;
    private string _connectionId = Guid.NewGuid().ToString("N");

    private sealed class PendingWrite(byte[] bytes)
    {
        public byte[] Bytes { get; } = bytes;
        public int Offset { get; set; }
        public TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>Created on the protocol thread when TCP accepts a connection.</summary>
    public TcpCoreConnection(TcpCoreHostService host, TcpConnection tcp)
    {
        _host = host;
        _tcp = tcp;
        Transport = new DuplexPipe(_inbound.Reader, _outbound.Writer);
        LocalEndPoint = new IPEndPoint(host.Address, tcp.LocalPort);
        RemoteEndPoint = new IPEndPoint(tcp.RemoteAddress, tcp.RemotePort);
        tcp.DataAvailable += OnDataAvailable;
        tcp.ReadClosed += OnReadClosed;
        tcp.SendReady += OnSendReady;
        tcp.StateChanged += OnStateChanged;
        _inputPump = Task.Run(PumpInputAsync);
        _outputPump = Task.Run(PumpOutputAsync);
    }

    public override string ConnectionId { get => _connectionId; set => _connectionId = value; }
    public override IFeatureCollection Features { get; } = new FeatureCollection();
    public override IDictionary<object, object?> Items { get; set; } = new Dictionary<object, object?>();
    public override IDuplexPipe Transport { get; set; }
    public override EndPoint? LocalEndPoint { get; set; }
    public override EndPoint? RemoteEndPoint { get; set; }
    public override CancellationToken ConnectionClosed => _closed.Token;

    private bool IsDetached => Volatile.Read(ref _detached) != 0;

    // ---- Protocol-thread callbacks -------------------------------------------------------------

    private void OnDataAvailable(TcpConnection connection) => MoveInput();
    private void OnReadClosed(TcpConnection connection) => MoveInput();
    private void OnSendReady(TcpConnection connection) => DrainWrites();

    private void OnStateChanged(TcpConnection connection, TcpState state)
    {
        if (state == TcpState.Closed)
            Detach(connection.FailureReason is null ? null : new ConnectionResetException(connection.FailureReason));
    }

    /// <summary>Moves buffered TCP bytes into the bounded input queue; completes input at EOF.</summary>
    private void MoveInput()
    {
        if (IsDetached) return;
        while (_tcp.Available > 0 && Volatile.Read(ref _queuedInputBytes) < InputQueueLimitBytes)
        {
            var count = Math.Min(Math.Min(_tcp.Available, InputChunkBytes), InputQueueLimitBytes - Volatile.Read(ref _queuedInputBytes));
            var bytes = new byte[count];
            var read = _tcp.Read(bytes);
            if (read == 0) break;
            if (read != count) Array.Resize(ref bytes, read);
            Interlocked.Add(ref _queuedInputBytes, read);
            if (!_input.Writer.TryWrite(bytes)) return; // Detached concurrently.
        }
        // Peer FIN is delivered only after every received byte has been queued.
        if (_tcp.PeerClosed && _tcp.Available == 0) _input.Writer.TryComplete();
    }

    /// <summary>Offers queued response bytes to TCP; completes each write once TCP has accepted all of it.</summary>
    private void DrainWrites()
    {
        Exception? failure = null;
        lock (_writeGate)
        {
            while (_pendingWrites.TryPeek(out var pending))
            {
                int accepted;
                try { accepted = _tcp.Send(pending.Bytes.AsSpan(pending.Offset)); }
                catch (InvalidOperationException error) { failure = new IOException(error.Message, error); break; }
                pending.Offset += accepted;
                if (pending.Offset != pending.Bytes.Length) break; // Resume on SendReady.
                _pendingWrites.Dequeue();
                pending.Completion.TrySetResult();
            }
        }
        if (failure is not null) FailPendingWrites(failure);
    }

    // ---- Pumps (thread pool) -------------------------------------------------------------------

    private async Task PumpInputAsync()
    {
        Exception? error = null;
        try
        {
            while (await _input.Reader.WaitToReadAsync(_pumpAbort.Token))
            {
                while (_input.Reader.TryRead(out var bytes))
                {
                    var flush = await _inbound.Writer.WriteAsync(bytes, _pumpAbort.Token);
                    Interlocked.Add(ref _queuedInputBytes, -bytes.Length);
                    if (flush.IsCompleted) return; // Kestrel stopped reading.
                }
                // The queue drained: let the protocol thread move any bytes TCP is still holding. Without
                // this, data that arrived while the queue was full (including a FIN) would never be read.
                await ScheduleWithRetryAsync(MoveInput);
            }
        }
        catch (OperationCanceledException) when (_pumpAbort.IsCancellationRequested)
        {
            error = new ConnectionAbortedException("The TCP.Core connection was aborted.");
        }
        catch (Exception failure) { error = failure; }
        finally { await _inbound.Writer.CompleteAsync(error); }
    }

    private async Task PumpOutputAsync()
    {
        var completed = false;
        Exception? error = null;
        try
        {
            while (true)
            {
                var result = await _outbound.Reader.ReadAsync(_pumpAbort.Token);
                if (result.IsCanceled) break;
                foreach (var segment in result.Buffer)
                    for (var offset = 0; offset < segment.Length; offset += OutputChunkBytes)
                        await SendAsync(segment.Slice(offset, Math.Min(OutputChunkBytes, segment.Length - offset)).ToArray());
                _outbound.Reader.AdvanceTo(result.Buffer.End);
                if (result.IsCompleted) { completed = true; break; }
            }
        }
        catch (OperationCanceledException) when (_pumpAbort.IsCancellationRequested) { }
        catch (Exception failure) { error = failure; }
        await _outbound.Reader.CompleteAsync(error);
        if (!completed || error is not null) return;
        try
        {
            // Every response byte is in TCP's send buffer; half-close after it (FIN).
            await _host.RunOnProtocolThreadAsync(() =>
            {
                if (_tcp.State is TcpState.Established or TcpState.CloseWait) _tcp.Close();
            }, CancellationToken.None);
            _outputClosedGracefully = true;
        }
        catch (IOException) { } // Stack stopped; nothing left to close.
    }

    private async Task SendAsync(byte[] bytes)
    {
        var pending = new PendingWrite(bytes);
        await _host.RunOnProtocolThreadAsync(() =>
        {
            if (IsDetached || _tcp.State is not (TcpState.Established or TcpState.CloseWait))
                throw new IOException("The TCP connection closed while Kestrel was writing.");
            lock (_writeGate) _pendingWrites.Enqueue(pending);
            DrainWrites();
        }, _pumpAbort.Token);
        await pending.Completion.Task.WaitAsync(_pumpAbort.Token);
    }

    private async Task ScheduleWithRetryAsync(Action action)
    {
        // The command queue is bounded; retry briefly rather than lose the wakeup.
        while (!_host.TrySchedule(action))
        {
            if (_host.Failure is not null) throw new IOException("The TCP.Core protocol thread stopped.", _host.Failure);
            await Task.Delay(ResumeRetryDelay, _pumpAbort.Token);
        }
    }

    // ---- Teardown ------------------------------------------------------------------------------

    private void FailPendingWrites(Exception error)
    {
        lock (_writeGate)
            while (_pendingWrites.TryDequeue(out var pending)) pending.Completion.TrySetException(error);
    }

    /// <summary>
    /// Stops exchanging data with TCP. Idempotent and callable from any thread. Received bytes already
    /// queued are still delivered unless the pumps are aborted.
    /// </summary>
    private void Detach(Exception? error)
    {
        if (Interlocked.Exchange(ref _detached, 1) != 0) return;
        _tcp.DataAvailable -= OnDataAvailable;
        _tcp.ReadClosed -= OnReadClosed;
        _tcp.SendReady -= OnSendReady;
        _tcp.StateChanged -= OnStateChanged;
        _input.Writer.TryComplete(error);
        FailPendingWrites(error ?? new IOException("The TCP connection closed."));
        _outbound.Reader.CancelPendingRead();
        if (error is not null) _pumpAbort.Cancel();
        // Signal Kestrel on the thread pool so its continuations never run on the protocol thread.
        _ = _closed.CancelAsync();
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        _host.TrySchedule(() =>
        {
            if (_tcp.State is not (TcpState.Closed or TcpState.TimeWait)) _tcp.Abort(); // RST
        });
        Detach(abortReason);
    }

    public override void Abort() => Abort(new ConnectionAbortedException("Kestrel aborted the TCP.Core connection."));

    /// <summary>
    /// Kestrel is finished with the connection. As with Kestrel's socket transport, disposal completes
    /// the application-facing pipe ends: the output pump then flushes the remaining response bytes and
    /// sends FIN, and TCP keeps closing gracefully inside TcpHost. Output that cannot drain is reset.
    /// </summary>
    public override async ValueTask DisposeAsync()
    {
        await _outbound.Writer.CompleteAsync(); // No more response bytes.
        await _inbound.Reader.CompleteAsync();  // The application no longer reads; releases the input pump.
        _input.Writer.TryComplete();
        if (await Task.WhenAny(_outputPump, Task.Delay(OutputDrainTimeout)) != _outputPump || !_outputClosedGracefully)
            Abort(new ConnectionAbortedException("Kestrel disposed the connection before its output completed."));
        _pumpAbort.Cancel();
        await Task.WhenAll(_inputPump, _outputPump);
        Detach(null);
        _pumpAbort.Dispose();
    }

    private sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;
        public PipeWriter Output { get; } = output;
    }
}
