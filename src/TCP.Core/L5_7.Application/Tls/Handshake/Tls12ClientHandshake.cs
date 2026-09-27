using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The TLS 1.2 ECDHE client after ServerHello (RFC 5246 7.3, RFC 8422): check the certificate and the signed key
/// exchange, send our public key, switch keys, and exchange Finished messages.
/// </summary>
/// <remarks>
/// The ServerKeyExchange signature is what defeats a man in the middle in TLS 1.2: the server signs its ephemeral
/// key together with both hello randoms, so an attacker cannot substitute its own key without the certificate's
/// private key. The Finished messages then confirm that both sides saw the same handshake.
/// </remarks>
internal sealed class Tls12ClientHandshake : HandshakeProtocol
{
    private enum State { WaitCertificate, WaitServerKeyExchange, WaitServerHelloDone, WaitChangeCipherSpec, WaitFinished, Connected }

    private readonly CipherSuiteInfo _suite;
    private readonly ClientHello _hello;
    private readonly ServerHello _serverHello;
    private State _state = State.WaitCertificate;
    private bool _certificateRequested;
    private TlsKeyExchange? _keyExchange;
    private byte[] _premasterSecret = [];
    private byte[] _masterSecret = [];
    private RecordProtection? _pendingRead;

    /// <summary>Continues after a TLS 1.2 ServerHello, checking the extensions it answered with.</summary>
    public Tls12ClientHandshake(TlsEngine engine, CipherSuiteInfo suite, ClientHello hello, ServerHello serverHello) : base(engine)
    {
        _suite = suite;
        _hello = hello;
        _serverHello = serverHello;
        foreach (var extension in serverHello.Extensions)
            Require(hello.Extensions.Has(extension.Type), TlsAlertDescription.UnsupportedExtension, TlsMessages.ExtensionNotOffered);
        if (serverHello.Extensions.Find(ExtensionType.RenegotiationInfo) is { } renegotiation)
            Require(SimpleExtensions.IsInitialRenegotiationInfo(renegotiation), TlsAlertDescription.HandshakeFailure, TlsMessages.RenegotiationInfoInvalid);
        if (serverHello.Extensions.Find(ExtensionType.ApplicationLayerProtocolNegotiation) is { } alpn)
        {
            var offered = AlpnExtension.Parse(hello.Extensions.Find(ExtensionType.ApplicationLayerProtocolNegotiation)!);
            var selected = AlpnExtension.Parse(alpn);
            Require(selected is [{ } protocol] && offered.Contains(protocol), TlsAlertDescription.IllegalParameter, TlsMessages.ProtocolNotOffered);
            Engine.ApplicationProtocol = selected[0];
        }
        // RFC 7627 5.2: the extended master secret is used only if both hellos carry the extension.
        Engine.ExtendedMasterSecret = serverHello.Extensions.Has(ExtensionType.ExtendedMasterSecret);
    }

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        switch (_state, message.Type)
        {
            case (State.WaitCertificate, HandshakeType.Certificate):
                ClientHandshake.ValidateServerCertificate(Engine, CertificateMessage.Parse(message.Body, TlsVersion.Tls12));
                Engine.Transcript.Add(message.Raw);
                _state = State.WaitServerKeyExchange;
                break;
            case (State.WaitServerKeyExchange, HandshakeType.ServerKeyExchange):
                OnServerKeyExchange(message);
                break;
            case (State.WaitServerHelloDone, HandshakeType.CertificateRequest):
                _certificateRequested = true;
                Engine.Transcript.Add(message.Raw);
                break;
            case (State.WaitServerHelloDone, HandshakeType.ServerHelloDone):
                Require(message.Body.IsEmpty, TlsAlertDescription.DecodeError, TlsMessages.TrailingBytes);
                Engine.Transcript.Add(message.Raw);
                SendSecondFlight();
                break;
            case (State.WaitFinished, HandshakeType.Finished):
                OnServerFinished(message);
                break;
            default:
                throw Unexpected(message);
        }
    }

    /// <summary>The server's ChangeCipherSpec: its records now use the negotiated keys.</summary>
    public override void OnChangeCipherSpec()
    {
        if (_state != State.WaitChangeCipherSpec) base.OnChangeCipherSpec();
        Engine.SetReadProtection(_pendingRead!);
        _state = State.WaitFinished;
    }

    /// <summary>A HelloRequest asks us to renegotiate, which we refuse with a warning (RFC 5746 4.2).</summary>
    public override void OnPostHandshakeMessage(HandshakeMessage message)
    {
        if (message.Type != HandshakeType.HelloRequest) throw Unexpected(message);
        Engine.SendWarningAlert(TlsAlertDescription.NoRenegotiation);
    }

    /// <summary>
    /// RFC 8422 5.4: the curve must be one we offered, the signature scheme one we offered and of the kind the
    /// suite names, and the signature must cover both randoms and the parameters.
    /// </summary>
    private void OnServerKeyExchange(HandshakeMessage message)
    {
        var keyExchange = ServerKeyExchange.Parse(message.Body);
        var groups = CodePointListExtension.Parse<TlsNamedGroup>(_hello.Extensions.Find(ExtensionType.SupportedGroups) ?? []);
        Require(groups.Contains(keyExchange.Group), TlsAlertDescription.IllegalParameter, TlsMessages.WrongKeyShareGroup);
        var schemes = CodePointListExtension.Parse<TlsSignatureScheme>(_hello.Extensions.Find(ExtensionType.SignatureAlgorithms) ?? []);
        var scheme = keyExchange.Signed.Scheme;
        Require(schemes.Contains(scheme) && TlsSignatures.Family(scheme) == _suite.Authentication,
            TlsAlertDescription.IllegalParameter, TlsMessages.SchemeNotOffered);
        var content = ServerKeyExchange.SignedContent(_hello.Random, _serverHello.Random,
            ServerKeyExchange.EncodeParameters(keyExchange.Group, keyExchange.PublicKey));
        Require(TlsSignatures.Verify(scheme, Engine.PeerCertificate!, content, keyExchange.Signed.Signature, TlsVersion.Tls12),
            TlsAlertDescription.DecryptError, TlsMessages.SignatureInvalid);
        _keyExchange = Options.KeyExchangeFactory(keyExchange.Group)
            ?? throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.WrongKeyShareGroup);
        _premasterSecret = _keyExchange.DeriveSharedSecret(keyExchange.PublicKey);
        Engine.Group = keyExchange.Group;
        Engine.SignatureScheme = scheme;
        Engine.Transcript.Add(message.Raw);
        _state = State.WaitServerHelloDone;
    }

    /// <summary>
    /// Certificate (empty, if one was requested), ClientKeyExchange, then the master secret and keys,
    /// ChangeCipherSpec, and Finished under the new keys.
    /// </summary>
    private void SendSecondFlight()
    {
        if (_certificateRequested)
            Engine.SendHandshake(new CertificateMessage { Certificates = [] }.Serialize(TlsVersion.Tls12));
        Engine.SendHandshake(SimpleMessages.ClientKeyExchange(_keyExchange!.PublicKey));
        _keyExchange.Dispose();
        _masterSecret = Engine.ExtendedMasterSecret
            ? Tls12Prf.ExtendedMasterSecret(_suite.Hash, _premasterSecret, Engine.Transcript.Hash(_suite.Hash))
            : Tls12Prf.MasterSecret(_suite.Hash, _premasterSecret, _hello.Random, _serverHello.Random);
        var (clientKey, serverKey, clientIv, serverIv) = Tls12Prf.KeyBlock(_suite, _masterSecret, _hello.Random, _serverHello.Random);
        _pendingRead = new Tls12RecordProtection(_suite, serverKey, serverIv);
        Engine.SendChangeCipherSpec();
        Engine.SetWriteProtection(new Tls12RecordProtection(_suite, clientKey, clientIv));
        Engine.SendHandshake(SimpleMessages.Finished(
            Tls12Prf.VerifyData(_suite.Hash, _masterSecret, fromServer: false, Engine.Transcript.Hash(_suite.Hash))));
        _state = State.WaitChangeCipherSpec;
    }

    /// <summary>The server's Finished covers everything including ours; once it checks out, the handshake is done.</summary>
    private void OnServerFinished(HandshakeMessage message)
    {
        var expected = Tls12Prf.VerifyData(_suite.Hash, _masterSecret, fromServer: true, Engine.Transcript.Hash(_suite.Hash));
        Require(CryptographicOperations.FixedTimeEquals(message.Body, expected), TlsAlertDescription.DecryptError, TlsMessages.FinishedMismatch);
        Engine.Transcript.Add(message.Raw);
        Engine.EnableApplicationData();
        _state = State.Connected;
        Engine.CompleteHandshake();
    }
}
