using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The TLS 1.2 ECDHE server handshake (RFC 5246 7.3, RFC 8422, RFC 7627): two round trips.
/// </summary>
/// <remarks>
/// <code>
///        Client                                           Server
///        ClientHello                      --------&gt;
///                                                         ServerHello
///                                                         Certificate
///                                                         ServerKeyExchange   (signed ECDHE public key)
///                                         &lt;--------      ServerHelloDone
///        ClientKeyExchange                                (client's ECDHE public key)
///        [ChangeCipherSpec]
///        Finished                         --------&gt;
///                                                         [ChangeCipherSpec]
///                                         &lt;--------      Finished
///        Application Data                 &lt;-------&gt;      Application Data
/// </code>
/// Unlike TLS 1.3, the certificate and most of the handshake travel in the clear, and the keys only change when
/// each side sends ChangeCipherSpec. Both sides compute the premaster secret from ECDHE, stretch it into a master
/// secret, and expand that into the record keys (see <see cref="Tls12Prf"/>).
/// </remarks>
internal sealed class Tls12ServerHandshake(TlsEngine engine, CipherSuiteInfo suite, TlsSigner signer) : HandshakeProtocol(engine)
{
    private const int DowngradeSentinelOffset = ClientHello.RandomLength - 8;
    /// <summary>TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 3.3).</summary>
    private const ushort RenegotiationSignalingSuite = 0x00FF;

    private enum State { WaitClientKeyExchange, WaitChangeCipherSpec, WaitFinished, Connected }

    private State _state;
    private ClientHello? _hello;
    private byte[] _serverRandom = [];
    private TlsKeyExchange? _keyExchange;
    private byte[] _masterSecret = [];
    private RecordProtection? _pendingRead;
    private RecordProtection? _pendingWrite;

    private TlsServerOptions ServerOptions => (TlsServerOptions)Options;

    /// <summary>Answers the ClientHello with the server's whole first flight.</summary>
    public void Start(ClientHello hello, HandshakeMessage message)
    {
        _hello = hello;
        Engine.Transcript.Add(message.Raw);
        Require(hello.CompressionMethods.Contains(ClientHello.NullCompression), TlsAlertDescription.IllegalParameter, TlsMessages.CompressionOffered);

        // RFC 8422 4: a client that omits supported_groups is taken to support any curve.
        var offeredGroups = hello.Extensions.Find(ExtensionType.SupportedGroups) is { } groupData
            ? CodePointListExtension.Parse<TlsNamedGroup>(groupData) : null;
        var group = Options.Groups.FirstOrDefault(g => offeredGroups is null || offeredGroups.Contains(g));
        Require(group != default, TlsAlertDescription.HandshakeFailure, TlsMessages.NoCommonGroup);
        var pointFormats = hello.Extensions.Find(ExtensionType.EcPointFormats);
        Require(pointFormats is null || SimpleExtensions.AllowsUncompressedPoints(pointFormats),
            TlsAlertDescription.IllegalParameter, TlsMessages.NoUncompressedPoints);
        var scheme = ServerHandshake.ChooseSignatureScheme(signer, TlsVersion.Tls12, hello);
        var protocol = ServerHandshake.SelectApplicationProtocol(Options, hello);
        var serverName = ServerHandshake.ServerNameOf(hello);
        var extendedMasterSecret = hello.Extensions.Has(ExtensionType.ExtendedMasterSecret);
        // RFC 5746 3.6: the client signals secure renegotiation with an empty extension or the special suite.
        var renegotiationInfo = hello.Extensions.Find(ExtensionType.RenegotiationInfo);
        Require(renegotiationInfo is null || SimpleExtensions.IsInitialRenegotiationInfo(renegotiationInfo),
            TlsAlertDescription.HandshakeFailure, TlsMessages.RenegotiationInfoInvalid);
        var secureRenegotiation = renegotiationInfo is not null || hello.CipherSuites.Contains(RenegotiationSignalingSuite);

        _serverRandom = NewRandom();
        if (Options.Enables(TlsVersion.Tls13)) ServerHello.Tls12DowngradeSentinel.CopyTo(_serverRandom, DowngradeSentinelOffset);
        List<TlsExtension> extensions = [];
        if (secureRenegotiation) extensions.Add(SimpleExtensions.InitialRenegotiationInfo);
        if (extendedMasterSecret) extensions.Add(SimpleExtensions.ExtendedMasterSecret);
        if (pointFormats is not null) extensions.Add(SimpleExtensions.UncompressedPointFormats);
        if (serverName is not null) extensions.Add(ServerNameExtension.Acknowledgment);
        if (protocol is not null) extensions.Add(AlpnExtension.Create([protocol]));
        // An empty session id tells the client this session cannot be resumed; we keep no session cache.
        Engine.SendHandshake(new ServerHello { Random = _serverRandom, CipherSuite = (ushort)suite.Suite, Extensions = extensions }.Serialize());

        List<byte[]> chain = [ServerOptions.Certificate.RawData, .. (ServerOptions.CertificateChain ?? []).Select(c => c.RawData)];
        Engine.SendHandshake(new CertificateMessage { Certificates = chain }.Serialize(TlsVersion.Tls12));

        _keyExchange = Options.KeyExchangeFactory(group) ?? throw new TlsAlertException(TlsAlertDescription.InternalError, TlsMessages.NoCommonGroup);
        var parameters = ServerKeyExchange.EncodeParameters(group, _keyExchange.PublicKey);
        var signature = signer.Sign(scheme, ServerKeyExchange.SignedContent(hello.Random, _serverRandom, parameters));
        Engine.SendHandshake(new ServerKeyExchange { Group = group, PublicKey = _keyExchange.PublicKey, Signed = new(scheme, signature) }.Serialize());
        Engine.SendHandshake(SimpleMessages.ServerHelloDone());

        Engine.Group = group;
        Engine.SignatureScheme = scheme;
        Engine.ApplicationProtocol = protocol;
        Engine.ServerName = serverName;
        Engine.ExtendedMasterSecret = extendedMasterSecret;
        _state = State.WaitClientKeyExchange;
    }

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        switch (_state, message.Type)
        {
            case (State.WaitClientKeyExchange, HandshakeType.ClientKeyExchange):
                OnClientKeyExchange(message);
                break;
            case (State.WaitFinished, HandshakeType.Finished):
                OnClientFinished(message);
                break;
            default:
                throw Unexpected(message);
        }
    }

    /// <summary>The client's ChangeCipherSpec: from now on its records use the negotiated keys.</summary>
    public override void OnChangeCipherSpec()
    {
        if (_state != State.WaitChangeCipherSpec) base.OnChangeCipherSpec();
        Engine.SetReadProtection(_pendingRead!);
        _state = State.WaitFinished;
    }

    /// <summary>RFC 5746 4.4 / 5246 7.2.2: refuse renegotiation with a warning, keeping the connection.</summary>
    public override void OnPostHandshakeMessage(HandshakeMessage message)
    {
        if (message.Type != HandshakeType.ClientHello) throw Unexpected(message);
        Engine.SendWarningAlert(TlsAlertDescription.NoRenegotiation);
    }

    /// <summary>
    /// Computes the premaster secret from the client's public key, the master secret (extended, RFC 7627, when the
    /// client offered it), and the key block; the keys wait until each side's ChangeCipherSpec.
    /// </summary>
    private void OnClientKeyExchange(HandshakeMessage message)
    {
        var premasterSecret = _keyExchange!.DeriveSharedSecret(SimpleMessages.ParseClientKeyExchange(message.Body));
        _keyExchange.Dispose();
        Engine.Transcript.Add(message.Raw);
        _masterSecret = Engine.ExtendedMasterSecret
            ? Tls12Prf.ExtendedMasterSecret(suite.Hash, premasterSecret, Engine.Transcript.Hash(suite.Hash))
            : Tls12Prf.MasterSecret(suite.Hash, premasterSecret, _hello!.Random, _serverRandom);
        var (clientKey, serverKey, clientIv, serverIv) = Tls12Prf.KeyBlock(suite, _masterSecret, _hello!.Random, _serverRandom);
        _pendingRead = new Tls12RecordProtection(suite, clientKey, clientIv);
        _pendingWrite = new Tls12RecordProtection(suite, serverKey, serverIv);
        _state = State.WaitChangeCipherSpec;
    }

    /// <summary>Verifies the client's Finished, then sends ChangeCipherSpec and our Finished under the new keys.</summary>
    private void OnClientFinished(HandshakeMessage message)
    {
        var expected = Tls12Prf.VerifyData(suite.Hash, _masterSecret, fromServer: false, Engine.Transcript.Hash(suite.Hash));
        Require(CryptographicOperations.FixedTimeEquals(message.Body, expected), TlsAlertDescription.DecryptError, TlsMessages.FinishedMismatch);
        Engine.Transcript.Add(message.Raw);
        Engine.SendChangeCipherSpec();
        Engine.SetWriteProtection(_pendingWrite!);
        Engine.SendHandshake(SimpleMessages.Finished(
            Tls12Prf.VerifyData(suite.Hash, _masterSecret, fromServer: true, Engine.Transcript.Hash(suite.Hash))));
        Engine.EnableApplicationData();
        _state = State.Connected;
        Engine.CompleteHandshake();
    }
}
