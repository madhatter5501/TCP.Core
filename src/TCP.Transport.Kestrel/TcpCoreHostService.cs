using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Hosting;
using TCP.L4.Transport.Tcp;
using TCP.Networking.Pcap;
using TCP.Stack;

namespace TCP.Transport.Kestrel;

/// <summary>
/// Owns the <see cref="EthernetStack"/> and its single protocol thread. The stack starts before Kestrel
/// binds (<see cref="StartingAsync"/>) and stops only after Kestrel has drained its connections
/// (<see cref="StoppedAsync"/>), so graceful TCP closes can still complete during shutdown.
/// </summary>
public sealed class TcpCoreHostService : IHostedLifecycleService, IAsyncDisposable
{
    private static readonly TimeSpan ProtocolThreadJoinTimeout = TimeSpan.FromSeconds(5);
    private const string ProtocolThreadName = "TCP.Core protocol thread";

    private readonly TcpCoreServerOptions _options;
    private readonly Func<EthernetStack> _stackFactory;
    private readonly IHostApplicationLifetime? _lifetime;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<EthernetStack> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Lock _startGate = new();
    private EthernetStack? _stack;
    private Thread? _thread;
    private int _stopped;

    public TcpCoreHostService(TcpCoreServerOptions options) : this(options, null, null) { }

    internal TcpCoreHostService(TcpCoreServerOptions options, Func<EthernetStack>? stackFactory, IHostApplicationLifetime? lifetime)
    {
        _options = options;
        _stackFactory = stackFactory ?? (() =>
            PcapNetworkConfiguration.CreateStack(options.InterfaceName, options.Address, options.Gateway, options.Mtu));
        _lifetime = lifetime;
    }

    public IPAddress Address => _options.Address;

    /// <summary>The exception that stopped the protocol thread, such as an address conflict or interface failure.</summary>
    public Exception? Failure { get; private set; }

    public Task StartingAsync(CancellationToken cancellationToken) => EnsureStartedAsync(cancellationToken);
    public Task StartAsync(CancellationToken cancellationToken) => EnsureStartedAsync(cancellationToken);
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    // Kestrel drains and closes connections during its own StopAsync; the stack must outlive that.
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppedAsync(CancellationToken cancellationToken) { Shutdown(); return Task.CompletedTask; }

    /// <summary>Starts the stack once and waits until its address claim completes.</summary>
    internal Task<EthernetStack> EnsureStartedAsync(CancellationToken cancellationToken)
    {
        lock (_startGate)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _stopped) != 0, this);
            if (_thread is null)
            {
                var stack = _stackFactory();
                stack.AddressClaimed += () => _ready.TrySetResult(stack);
                _stack = stack;
                _thread = new Thread(RunStack) { IsBackground = true, Name = ProtocolThreadName };
                _thread.Start();
            }
        }
        return _ready.Task.WaitAsync(cancellationToken);
    }

    internal async Task<TcpHost> GetTcpHostAsync(CancellationToken cancellationToken) =>
        (await EnsureStartedAsync(cancellationToken)).Tcp;

    private void RunStack()
    {
        try { _stack!.Run(_stop.Token); }
        catch (Exception error)
        {
            // Address conflicts and interface failures end the protocol thread. Fail pending work and
            // stop the application instead of silently serving nothing.
            Failure = error;
            if (!_ready.TrySetException(error)) _lifetime?.StopApplication();
        }
        finally
        {
            _ready.TrySetCanceled();
            if (!_stop.IsCancellationRequested) _stop.Cancel();
        }
    }

    /// <summary>
    /// Queues work for the protocol thread. Returns false when the stack is stopped or its command queue
    /// is full. Exceptions from <paramref name="action"/> are contained so one connection cannot stop the stack.
    /// </summary>
    internal bool TrySchedule(Action action)
    {
        var stack = _stack;
        if (stack is null || _stop.IsCancellationRequested) return false;
        return stack.TrySchedule(() =>
        {
            try { action(); }
            catch (Exception error) { Trace.TraceError($"TCP.Core protocol command failed: {error}"); }
        });
    }

    /// <summary>Runs <paramref name="action"/> on the protocol thread and waits for it. Fails fast once the stack stops.</summary>
    internal async Task RunOnProtocolThreadAsync(Action action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TrySchedule(() =>
        {
            try { action(); completion.TrySetResult(); }
            catch (Exception error) { completion.TrySetException(error); }
        }))
            throw new IOException("The TCP.Core protocol thread is stopped or its command queue is full.", Failure);
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        try { await completion.Task.WaitAsync(wait.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("The TCP.Core protocol thread stopped before the command ran.", Failure);
        }
    }

    private void Shutdown()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        _stop.Cancel();
        if (_thread is { } thread && thread != Thread.CurrentThread && !thread.Join(ProtocolThreadJoinTimeout))
        {
            Trace.TraceError("TCP.Core protocol thread did not stop within the shutdown timeout.");
            return; // Leave the stack to the background thread rather than disposing it underneath.
        }
        _stack?.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Shutdown();
        return ValueTask.CompletedTask;
    }
}
