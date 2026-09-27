using System.Security.Cryptography.X509Certificates;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls;

/// <summary>
/// A TLS connection over a <see cref="TcpConnection"/>: an encrypted, authenticated byte stream with the same
/// event-driven shape as TCP's (<see cref="Send"/>, <see cref="Read"/>, <see cref="DataAvailable"/>,
/// <see cref="ReadClosed"/>, <see cref="SendReady"/>).
/// </summary>
/// <remarks>
/// <para>
/// TLS sits between TCP and the application. TCP delivers bytes reliably and in order but offers no secrecy and
/// no proof of who is on the other end; TLS adds both. It frames the stream into records, runs a handshake that
/// authenticates the server by certificate and agrees fresh keys by Diffie-Hellman, then encrypts and
/// authenticates every record with those keys. See <c>README.md</c> in this folder for the full picture.
/// </para>
/// <para>
/// All protocol work happens in a transport-independent <see cref="TlsEngine"/>; this class only moves bytes
/// between it and TCP. Like <see cref="TcpConnection"/>, every member and callback runs on the stack's protocol
/// thread, and callbacks may call back in (to send, read, close or abort).
/// </para>
/// <para>
/// Flow control carries through: decrypted data is buffered only up to <see cref="MaximumReceiveBuffer"/>, after
/// which TLS stops reading from TCP, TCP's receive window fills, and the peer is slowed down; encrypted output is
/// buffered up to <see cref="MaximumSendBuffer"/>, beyond which <see cref="Send"/> accepts less and
/// <see cref="SendReady"/> announces room.
/// </para>
/// </remarks>
public sealed class TlsConnection
{
    /// <summary>Most encrypted bytes held for TCP before <see cref="Send"/> accepts fewer than offered.</summary>
    public const int MaximumSendBuffer = 1_048_576;
    /// <summary>Most decrypted bytes held for <see cref="Read"/> before TLS stops reading from TCP.</summary>
    public const int MaximumReceiveBuffer = 262_144;
    private const int TransportReadChunk = TlsRecord.HeaderLength + TlsRecord.MaximumTls12CiphertextLength;

    private readonly TlsEngine _engine;
    private readonly Queue<byte[]> _output = new();
    private int _outputOffset;
    private int _outputBytes;
    private bool _pumping;
    private bool _pumpRequested;
    private bool _newData;
    private bool _sendBlocked;
    private bool _handshakeNotified;
    private bool _readClosedNotified;
    private bool _closeTransportWhenFlushed;
    private bool _transportCloseRequested;
    private string? _failureReason;

    private TlsConnection(TcpConnection transport, TlsOptions options)
    {
        Transport = transport;
        _engine = new TlsEngine(options);
        transport.DataAvailable += _ => Pump();
        transport.SendReady += _ => Pump();
        transport.ReadClosed += _ => OnTransportReadClosed();
        transport.StateChanged += (_, state) => { if (state == TcpState.Closed) OnTransportClosed(); };
    }

    /// <summary>
    /// Runs the server side over an accepted TCP connection, typically from a <see cref="TcpHost.Listen"/> callback.
    /// The handshake starts when the client's ClientHello arrives.
    /// </summary>
    public static TlsConnection AuthenticateAsServer(TcpConnection transport, TlsServerOptions options)
    {
        var connection = new TlsConnection(transport, options);
        connection.Pump();
        return connection;
    }

    /// <summary>Runs the client side, sending ClientHello as soon as the TCP connection is established.</summary>
    public static TlsConnection AuthenticateAsClient(TcpConnection transport, TlsClientOptions options)
    {
        var connection = new TlsConnection(transport, options);
        if (transport.State is TcpState.Established or TcpState.CloseWait) connection.StartClient();
        else transport.Connected += _ => connection.StartClient();
        return connection;
    }

    /// <summary>The TCP connection underneath.</summary>
    public TcpConnection Transport { get; }

    /// <summary>Handshaking, established or closed; changes are announced through <see cref="StateChanged"/>.</summary>
    public TlsConnectionState State { get; private set; }

    /// <summary>This end is the server.</summary>
    public bool IsServer => _engine.IsServer;

    /// <summary>The negotiated protocol version.</summary>
    public TlsVersion? Version => _engine.Version;

    /// <summary>The negotiated cipher suite.</summary>
    public TlsCipherSuite? CipherSuite => _engine.Suite?.Suite;

    /// <summary>The (EC)DHE group of the key exchange.</summary>
    public TlsNamedGroup? KeyExchangeGroup => _engine.Group;

    /// <summary>The scheme of the server's handshake signature.</summary>
    public TlsSignatureScheme? SignatureScheme => _engine.SignatureScheme;

    /// <summary>The protocol ALPN selected, such as "h2", or null.</summary>
    public string? ApplicationProtocol => _engine.ApplicationProtocol;

    /// <summary>Server: the name the client asked for (SNI). Client: the configured target host.</summary>
    public string? ServerName => _engine.ServerName;

    /// <summary>Client: the server's validated certificate.</summary>
    public X509Certificate2? RemoteCertificate => _engine.PeerCertificate;

    /// <summary>TLS 1.2: the master secret was bound to the handshake transcript (RFC 7627).</summary>
    public bool ExtendedMasterSecret => _engine.ExtendedMasterSecret;

    /// <summary>TLS 1.3: the server asked for a different key share with a HelloRetryRequest.</summary>
    public bool HelloRetryRequested => _engine.HelloRetryRequested;

    /// <summary>TLS 1.3 KeyUpdates received from the peer.</summary>
    public int KeyUpdatesReceived => _engine.KeyUpdatesReceived;

    /// <summary>Why the connection ended abnormally, or null.</summary>
    public string? FailureReason => _failureReason ?? _engine.FailureReason;

    /// <summary>The fatal alert we sent the peer, if any.</summary>
    public TlsAlertDescription? AlertSent => _engine.AlertSent;

    /// <summary>The last alert the peer sent, if any.</summary>
    public TlsAlertDescription? AlertReceived => _engine.AlertReceived;

    /// <summary>Decrypted bytes ready for <see cref="Read"/>.</summary>
    public int Available => _engine.Available;

    /// <summary>The peer sent close_notify: every byte it will send has arrived.</summary>
    public bool PeerClosed => _engine.PeerClosed;

    /// <summary>Encrypted bytes waiting for room in TCP's send buffer.</summary>
    public int BufferedSendBytes => _outputBytes;

    /// <summary>The handshake finished; <see cref="Send"/> may be called.</summary>
    public event Action<TlsConnection>? HandshakeCompleted;

    /// <summary>New decrypted bytes can be read with <see cref="Read"/>.</summary>
    public event Action<TlsConnection>? DataAvailable;

    /// <summary>The peer sent close_notify; <see cref="PeerClosed"/> is now true.</summary>
    public event Action<TlsConnection>? ReadClosed;

    /// <summary>Output drained after <see cref="Send"/> accepted fewer bytes than offered.</summary>
    public event Action<TlsConnection>? SendReady;

    /// <summary>Raised on every state change, including the final one to <see cref="TlsConnectionState.Closed"/>.</summary>
    public event Action<TlsConnection, TlsConnectionState>? StateChanged;

    /// <summary>Encrypts and sends up to the free buffer capacity; returns how many bytes were accepted.</summary>
    /// <exception cref="InvalidOperationException">The handshake has not completed, or the connection is closing or closed.</exception>
    public int Send(ReadOnlySpan<byte> bytes)
    {
        var count = Math.Min(bytes.Length, Math.Max(0, MaximumSendBuffer - _outputBytes));
        _engine.Send(bytes[..count]);
        if (count < bytes.Length) _sendBlocked = true;
        Pump();
        return count;
    }

    /// <summary>Reads decrypted bytes. Zero means none are buffered; <see cref="PeerClosed"/> distinguishes the end.</summary>
    public int Read(Span<byte> destination)
    {
        var count = _engine.Read(destination);
        if (count > 0 && Transport.Available > 0) Pump(); // Room freed: resume reading from TCP.
        return count;
    }

    /// <summary>
    /// Sends close_notify and then closes TCP's sending side. Reading continues until the peer closes as well,
    /// which in TLS 1.2 it does at once and in TLS 1.3 when it is ready (RFC 8446 6.1).
    /// </summary>
    public void Close()
    {
        _engine.Close();
        _closeTransportWhenFlushed = true;
        Pump();
    }

    /// <summary>Resets the TCP connection at once, discarding everything buffered.</summary>
    public void Abort()
    {
        _failureReason ??= TlsMessages.LocallyAborted;
        Transport.Abort();
        UpdateState();
    }

    /// <summary>TLS 1.3: replace our sending keys and ask the peer to replace its own (RFC 8446 4.6.3).</summary>
    public void RequestKeyUpdate()
    {
        _engine.RequestKeyUpdate();
        Pump();
    }

    /// <summary>The TCP connection is up: send ClientHello.</summary>
    private void StartClient()
    {
        _engine.Start();
        Pump();
    }

    /// <summary>
    /// Moves bytes both ways and raises events. Callbacks may call back in; a nested call only asks the outer
    /// loop to run again, so the engine is never re-entered mid-record.
    /// </summary>
    private void Pump()
    {
        if (_pumping)
        {
            _pumpRequested = true;
            return;
        }
        _pumping = true;
        try
        {
            do
            {
                _pumpRequested = false;
                PullFromTransport();
                Flush();
                Notify();
            } while (_pumpRequested && State != TlsConnectionState.Closed);
        }
        finally
        {
            _pumping = false;
        }
    }

    /// <summary>Feeds TCP's bytes to the engine while there is room for their plaintext.</summary>
    private void PullFromTransport()
    {
        var buffer = new byte[TransportReadChunk];
        while (Transport.Available > 0)
        {
            var done = _engine.IsFailed || _engine.PeerClosed;
            // RFC 8446 6.1: data after close_notify is ignored, so it is drained and dropped.
            if (!done && _engine.Available >= MaximumReceiveBuffer) break;
            var count = Transport.Read(buffer);
            if (count == 0) break;
            if (done) continue;
            var before = _engine.Available;
            _engine.Receive(buffer.AsSpan(0, count));
            _newData |= _engine.Available > before;
        }
    }

    /// <summary>Hands the engine's records to TCP as far as its send buffer allows; closes TCP when asked and drained.</summary>
    private void Flush()
    {
        var bytes = _engine.TakeOutput();
        if (bytes.Length > 0)
        {
            _output.Enqueue(bytes);
            _outputBytes += bytes.Length;
        }
        if (_engine.IsFailed || (_engine.CloseNotifySent && _engine.PeerClosed)) _closeTransportWhenFlushed = true;
        // Once TCP's sending side is closed nothing more can go out (a late fatal alert, say), so it is dropped.
        if (_transportCloseRequested)
        {
            _output.Clear();
            _outputBytes = _outputOffset = 0;
        }
        while (_output.TryPeek(out var head) && Transport.State is TcpState.Established or TcpState.CloseWait)
        {
            var sent = Transport.Send(head.AsSpan(_outputOffset));
            _outputOffset += sent;
            _outputBytes -= sent;
            if (_outputOffset < head.Length) break; // TCP's buffer is full; SendReady resumes.
            _output.Dequeue();
            _outputOffset = 0;
        }
        if (_closeTransportWhenFlushed && _output.Count == 0 && !_transportCloseRequested)
        {
            _transportCloseRequested = true;
            Transport.Close();
        }
    }

    /// <summary>Raises the events for whatever changed. Each callback may close the connection, so state is re-checked.</summary>
    private void Notify()
    {
        if (!_handshakeNotified && _engine.HandshakeComplete && !_engine.IsFailed)
        {
            _handshakeNotified = true;
            SetState(TlsConnectionState.Established);
            HandshakeCompleted?.Invoke(this);
        }
        if (_newData && _engine.Available > 0)
        {
            _newData = false;
            DataAvailable?.Invoke(this);
        }
        if (_engine.PeerClosed && !_readClosedNotified)
        {
            _readClosedNotified = true;
            ReadClosed?.Invoke(this);
        }
        if (_sendBlocked && _outputBytes < MaximumSendBuffer / 2 && _engine.CanSend)
        {
            _sendBlocked = false;
            SendReady?.Invoke(this);
        }
        UpdateState();
    }

    /// <summary>
    /// TCP delivered FIN. After close_notify that is the normal end; without it an attacker could have cut the stream
    /// short, so it is reported as truncation (RFC 8446 6.1) unless we had already closed our side.
    /// </summary>
    private void OnTransportReadClosed()
    {
        Pump();
        if (!_engine.PeerClosed && !_engine.IsFailed && !_engine.CloseNotifySent)
            _failureReason ??= _engine.HandshakeComplete ? TlsMessages.Truncated : TlsMessages.ClosedDuringHandshake;
        if (_failureReason is not null && !_transportCloseRequested)
        {
            _transportCloseRequested = true;
            Transport.Close();
        }
        UpdateState();
    }

    /// <summary>TCP reached CLOSED: the TLS connection is over, abnormally if TCP failed first.</summary>
    private void OnTransportClosed()
    {
        if (State != TlsConnectionState.Closed && Transport.FailureReason is { } reason && !(_engine.PeerClosed && _engine.CloseNotifySent))
            _failureReason ??= reason;
        SetState(TlsConnectionState.Closed);
    }

    /// <summary>Closed once failed, once both close_notify alerts are exchanged, or once TCP is gone.</summary>
    private void UpdateState()
    {
        if (_engine.IsFailed || _failureReason is not null || (_engine.PeerClosed && _engine.CloseNotifySent) ||
            Transport.State == TcpState.Closed)
            SetState(TlsConnectionState.Closed);
    }

    private void SetState(TlsConnectionState state)
    {
        if (State == state || State == TlsConnectionState.Closed) return;
        State = state;
        StateChanged?.Invoke(this, state);
    }
}
