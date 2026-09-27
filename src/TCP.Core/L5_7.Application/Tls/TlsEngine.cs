using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TCP.L4.Transport.Tcp.Buffers;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Handshake;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls;

/// <summary>
/// The TLS protocol for one connection, independent of any transport: bytes from the peer go in through
/// <see cref="Receive"/>, bytes for the peer come out of <see cref="TakeOutput"/>.
/// </summary>
/// <remarks>
/// <para>
/// Keeping the protocol free of I/O ("sans-I/O") means the same code runs over <see cref="TlsConnection"/>'s TCP
/// stream and inside tests that feed it RFC 8448's recorded bytes and compare what it writes byte for byte.
/// </para>
/// <para>
/// The engine owns the sub-protocols that share the record layer. Handshake records are reassembled into messages
/// and passed to the current <see cref="HandshakeProtocol"/>, a per-version state machine that replaces itself as
/// the handshake learns the version. Alerts and application data are handled here. A protocol error anywhere
/// surfaces as a <see cref="TlsAlertException"/>, which becomes a fatal alert to the peer and ends the connection.
/// </para>
/// </remarks>
internal sealed class TlsEngine
{
    private const byte ChangeCipherSpecValue = 1;
    private const int AlertLength = 2;

    private readonly HandshakeReader _handshakeReader = new();
    private readonly ByteQueue _plaintext = new();
    private HandshakeProtocol _protocol;
    private bool _applicationDataReadable;
    private bool _compatibilityChangeCipherSpecSent;

    /// <summary>Creates the engine for a client or server, depending on the type of <paramref name="options"/>.</summary>
    public TlsEngine(TlsOptions options)
    {
        Options = options;
        IsServer = options is TlsServerOptions;
        _protocol = IsServer ? new ServerHandshake(this) : new ClientHandshake(this);
    }

    /// <summary>The configuration.</summary>
    public TlsOptions Options { get; }

    /// <summary>This end is the server.</summary>
    public bool IsServer { get; }

    /// <summary>The record layer, exposed for tests that inspect keys.</summary>
    internal RecordLayer Records { get; } = new();

    /// <summary>The handshake transcript.</summary>
    internal TranscriptHash Transcript { get; } = new();

    /// <summary>The current handshake state machine.</summary>
    internal HandshakeProtocol Protocol => _protocol;

    /// <summary>The negotiated version, once the hellos have settled it.</summary>
    public TlsVersion? Version { get; internal set; }

    /// <summary>The negotiated cipher suite.</summary>
    internal CipherSuiteInfo? Suite { get; set; }

    /// <summary>The key exchange group used.</summary>
    public TlsNamedGroup? Group { get; internal set; }

    /// <summary>The scheme of the server's handshake signature.</summary>
    public TlsSignatureScheme? SignatureScheme { get; internal set; }

    /// <summary>The ALPN protocol both ends agreed on, or null.</summary>
    public string? ApplicationProtocol { get; internal set; }

    /// <summary>The Server Name Indication a server received, or the name a client requested.</summary>
    public string? ServerName { get; internal set; }

    /// <summary>The peer's leaf certificate, once validated.</summary>
    public X509Certificate2? PeerCertificate { get; internal set; }

    /// <summary>TLS 1.2 used the extended master secret (RFC 7627).</summary>
    public bool ExtendedMasterSecret { get; internal set; }

    /// <summary>The server sent a HelloRetryRequest during this handshake.</summary>
    public bool HelloRetryRequested { get; internal set; }

    /// <summary>TLS 1.3 KeyUpdate messages received and acted on.</summary>
    public int KeyUpdatesReceived { get; internal set; }

    /// <summary>Both Finished messages have been exchanged; application data may flow.</summary>
    public bool HandshakeComplete { get; private set; }

    /// <summary>The peer sent close_notify: its direction has ended cleanly.</summary>
    public bool PeerClosed { get; private set; }

    /// <summary>We sent close_notify and will send no more application data.</summary>
    public bool CloseNotifySent { get; private set; }

    /// <summary>The connection ended with a fatal alert, sent or received.</summary>
    public bool IsFailed { get; private set; }

    /// <summary>Why the connection failed, or null.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>The fatal alert we sent, if any.</summary>
    public TlsAlertDescription? AlertSent { get; private set; }

    /// <summary>The last alert the peer sent, if any.</summary>
    public TlsAlertDescription? AlertReceived { get; private set; }

    /// <summary>Decrypted application bytes waiting for <see cref="Read"/>.</summary>
    public int Available => _plaintext.Count;

    /// <summary>Application data may be sent now.</summary>
    public bool CanSend => HandshakeComplete && !CloseNotifySent && !IsFailed;

    /// <summary>
    /// Some ClientHello has been sent or received. From then until the peer's Finished, TLS 1.3 tolerates a
    /// compatibility ChangeCipherSpec (RFC 8446 5).
    /// </summary>
    internal bool ClientHelloExchanged { get; set; }

    /// <summary>A client starts the handshake by sending its ClientHello; a server waits for one.</summary>
    public void Start()
    {
        if (_protocol is ClientHandshake client) Run(client.Start);
    }

    /// <summary>Processes bytes from the peer. Protocol errors do not throw; they fail the connection.</summary>
    public void Receive(ReadOnlySpan<byte> bytes)
    {
        if (IsFailed || PeerClosed) return;
        Records.Append(bytes);
        Run(ProcessRecords);
    }

    /// <summary>Removes the bytes waiting to be sent to the peer.</summary>
    public byte[] TakeOutput() => Records.TakeOutput();

    /// <summary>Moves up to <paramref name="destination"/>'s length of decrypted application data out.</summary>
    public int Read(Span<byte> destination) => _plaintext.Dequeue(destination);

    /// <summary>Encrypts <paramref name="data"/> as application_data records, split at the record size limit.</summary>
    /// <exception cref="InvalidOperationException">The handshake is not complete, or the connection is closing or failed.</exception>
    public void Send(ReadOnlySpan<byte> data)
    {
        if (!CanSend) throw new InvalidOperationException(TlsMessages.NotWritable);
        if (!data.IsEmpty) Records.Write(ContentType.ApplicationData, data);
    }

    /// <summary>
    /// Sends close_notify (RFC 8446 6.1): we will write nothing more. Without it, a peer cannot tell our clean end
    /// of stream from an attacker cutting the TCP connection short. Reading can continue until the peer closes too.
    /// </summary>
    public void Close()
    {
        if (IsFailed || CloseNotifySent) return;
        WriteAlert(TlsAlertLevel.Warning, TlsAlertDescription.CloseNotify);
        CloseNotifySent = true;
    }

    /// <summary>TLS 1.3: switch our sending keys and ask the peer to switch its own (RFC 8446 4.6.3).</summary>
    /// <exception cref="InvalidOperationException">Not an established TLS 1.3 connection.</exception>
    public void RequestKeyUpdate()
    {
        if (!CanSend || _protocol is not Tls13Handshake tls13) throw new InvalidOperationException(TlsMessages.KeyUpdateUnavailable);
        Run(() => tls13.SendKeyUpdate(requestPeerUpdate: true));
    }

    /// <summary>Fails the connection locally, sending <paramref name="alert"/> to the peer.</summary>
    public void Abort(TlsAlertDescription alert, string reason) => Fail(alert, reason, sendAlert: true);

    // ---- Services for the handshake protocols ----------------------------------------------------

    /// <summary>Sends a handshake message and appends it to the transcript.</summary>
    internal void SendHandshake(byte[] message)
    {
        Transcript.Add(message);
        Records.QueueHandshake(message);
    }

    /// <summary>Sends a post-handshake message, which is not part of the transcript.</summary>
    internal void SendPostHandshake(byte[] message) => Records.QueueHandshake(message);

    /// <summary>Sends a TLS 1.2 ChangeCipherSpec.</summary>
    internal void SendChangeCipherSpec() => Records.WriteChangeCipherSpec();

    /// <summary>
    /// TLS 1.3 compatibility mode (RFC 8446 D.4): one dummy ChangeCipherSpec, sent by the server right after its
    /// first handshake message and by the client before its second flight, when the client offered a session id.
    /// </summary>
    internal void SendCompatibilityChangeCipherSpec()
    {
        if (_compatibilityChangeCipherSpecSent) return;
        _compatibilityChangeCipherSpecSent = true;
        Records.WriteChangeCipherSpec();
    }

    /// <summary>A TLS 1.2 warning alert, which leaves the connection open (e.g. no_renegotiation).</summary>
    internal void SendWarningAlert(TlsAlertDescription description) => WriteAlert(TlsAlertLevel.Warning, description);

    /// <summary>
    /// Installs new read keys. RFC 8446 5.1: a handshake message must not span a key change, so any partial
    /// message still buffered is an unexpected_message.
    /// </summary>
    internal void SetReadProtection(RecordProtection protection)
    {
        RequireMessageBoundary();
        Records.SetReadProtection(protection);
    }

    /// <summary>Installs new write keys after flushing what was written under the old ones.</summary>
    internal void SetWriteProtection(RecordProtection protection) => Records.SetWriteProtection(protection);

    /// <summary>Hands the rest of the handshake to <paramref name="next"/>, e.g. once the version is known.</summary>
    internal void SwitchProtocol(HandshakeProtocol next) => _protocol = next;

    /// <summary>The peer's application keys are installed: application_data records are now legitimate.</summary>
    internal void EnableApplicationData() => _applicationDataReadable = true;

    /// <summary>Both Finished messages are done.</summary>
    internal void CompleteHandshake()
    {
        HandshakeComplete = true;
        Records.AcceptPlaintextAlerts = false;
    }

    // ---- Record dispatch -------------------------------------------------------------------------

    /// <summary>Runs one step, turning protocol errors into a fatal alert, and flushes the flight it wrote.</summary>
    private void Run(Action step)
    {
        try
        {
            step();
        }
        catch (TlsAlertException error)
        {
            Fail(error.Description, error.Message, sendAlert: true);
        }
        catch (CryptographicException error)
        {
            Fail(TlsAlertDescription.InternalError, error.Message, sendAlert: true);
        }
        Records.FlushHandshake();
    }

    /// <summary>Reads each complete record and routes it by content type (RFC 8446 5.1).</summary>
    private void ProcessRecords()
    {
        while (!IsFailed && !PeerClosed && Records.TryRead(out var type, out var data))
        {
            switch (type)
            {
                case ContentType.Handshake:
                    // RFC 8446 5.1: zero-length handshake fragments are not allowed.
                    if (data.Length == 0) throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.EmptyRecord);
                    _handshakeReader.Append(data);
                    while (!IsFailed && _handshakeReader.TryRead(out var message)) DispatchHandshake(message);
                    break;
                case ContentType.ChangeCipherSpec:
                    RequireMessageBoundary();
                    OnChangeCipherSpec(data);
                    break;
                case ContentType.Alert:
                    RequireMessageBoundary();
                    OnAlert(data);
                    break;
                case ContentType.ApplicationData:
                    RequireMessageBoundary();
                    if (!_applicationDataReadable)
                        throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.EarlyApplicationData);
                    _plaintext.Enqueue(data);
                    break;
                default:
                    throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.UnknownContentType);
            }
        }
    }

    /// <summary>Handshake messages go to the state machine; after the handshake, to its post-handshake handler.</summary>
    private void DispatchHandshake(HandshakeMessage message)
    {
        if (HandshakeComplete) _protocol.OnPostHandshakeMessage(message);
        else _protocol.OnMessage(message);
    }

    /// <summary>
    /// TLS 1.2: the peer switches to its new keys. TLS 1.3: a compatibility record to drop, allowed only between the
    /// first ClientHello and the peer's Finished (RFC 8446 5). Either way the body must be the single byte 1.
    /// </summary>
    private void OnChangeCipherSpec(byte[] data)
    {
        if (data is not [ChangeCipherSpecValue])
            throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.InvalidChangeCipherSpec);
        if (Version == TlsVersion.Tls12) _protocol.OnChangeCipherSpec();
        else if (!ClientHelloExchanged || HandshakeComplete)
            throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.InvalidChangeCipherSpec);
    }

    /// <summary>
    /// Alerts (RFC 8446 6): close_notify ends the peer's direction; user_canceled and TLS 1.2 warnings are noted
    /// and ignored; anything else is fatal, and is not answered with an alert of our own.
    /// </summary>
    private void OnAlert(byte[] data)
    {
        if (data.Length != AlertLength) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidAlert);
        var level = (TlsAlertLevel)data[0];
        var description = (TlsAlertDescription)data[1];
        AlertReceived = description;
        if (description == TlsAlertDescription.CloseNotify)
        {
            // Closing before the handshake finished abandons it: there is no connection to half-close.
            if (!HandshakeComplete) Fail(description, TlsMessages.PeerCanceledHandshake, sendAlert: false);
            PeerClosed = true;
            // RFC 5246 7.2.1: a TLS 1.2 peer must answer close_notify with its own. TLS 1.3 made closure half-duplex.
            if (Version == TlsVersion.Tls12) Close();
            return;
        }
        if (description == TlsAlertDescription.UserCanceled) return;
        if (Version == TlsVersion.Tls12 && level == TlsAlertLevel.Warning) return;
        Fail(description, string.Format(TlsMessages.PeerAlertFormat, description), sendAlert: false);
    }

    /// <summary>Ends the connection, optionally telling the peer why with a fatal alert.</summary>
    private void Fail(TlsAlertDescription description, string reason, bool sendAlert)
    {
        if (IsFailed) return;
        if (sendAlert)
        {
            WriteAlert(TlsAlertLevel.Fatal, description);
            AlertSent = description;
        }
        IsFailed = true;
        FailureReason = reason;
        _plaintext.Clear();
    }

    /// <summary>Writes a two-byte alert record under the current write keys.</summary>
    private void WriteAlert(TlsAlertLevel level, TlsAlertDescription description) =>
        Records.Write(ContentType.Alert, [(byte)level, (byte)description]);

    /// <summary>A partial handshake message may not be interrupted by another record type or a key change (RFC 8446 5.1).</summary>
    private void RequireMessageBoundary()
    {
        if (_handshakeReader.HasPartialMessage)
            throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.MessageSpansBoundary);
    }
}
