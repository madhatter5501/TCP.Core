using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The TLS 1.3 client after ServerHello (RFC 8446 4.3-4.4): read the server's encrypted flight, check its
/// certificate, signature and Finished, then send our own Finished.
/// </summary>
/// <remarks>
/// <para>
/// Each message is checked in order: EncryptedExtensions (nothing we did not offer), an optional
/// CertificateRequest, Certificate (a chain we trust for the name we asked for), CertificateVerify (the
/// certificate's key signed this very transcript, proving the server is not an impostor replaying a
/// certificate), and Finished (the server derived the same keys from the same messages).
/// </para>
/// <para>
/// A server that asks for a client certificate gets an empty Certificate message, as RFC 8446 4.4.2 lets a client
/// without one send; the server then decides whether to continue.
/// </para>
/// </remarks>
internal sealed class Tls13ClientHandshake : Tls13Handshake
{
    private enum State { WaitEncryptedExtensions, WaitCertificateOrRequest, WaitCertificate, WaitCertificateVerify, WaitFinished, Connected }

    private readonly ClientHello _hello;
    private State _state = State.WaitEncryptedExtensions;
    private byte[]? _certificateRequestContext;

    /// <summary>Continues after ServerHello: derives and installs the handshake traffic keys.</summary>
    public Tls13ClientHandshake(TlsEngine engine, CipherSuiteInfo suite, ClientHello hello, byte[] sharedSecret) : base(engine, suite)
    {
        _hello = hello;
        DeriveHandshakeSecrets(sharedSecret);
        Engine.SetReadProtection(Protection(ServerHandshakeSecret!));
        Engine.SetWriteProtection(Protection(ClientHandshakeSecret!));
        Engine.Records.AcceptPlaintextAlerts = true;
    }

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        switch (_state, message.Type)
        {
            case (State.WaitEncryptedExtensions, HandshakeType.EncryptedExtensions):
                OnEncryptedExtensions(message);
                break;
            case (State.WaitCertificateOrRequest, HandshakeType.CertificateRequest):
                _certificateRequestContext = SimpleMessages.ParseCertificateRequestContext(message.Body);
                Engine.Transcript.Add(message.Raw);
                _state = State.WaitCertificate;
                break;
            case (State.WaitCertificateOrRequest or State.WaitCertificate, HandshakeType.Certificate):
                var certificate = CertificateMessage.Parse(message.Body, TlsVersion.Tls13);
                Require(certificate.RequestContext.Length == 0, TlsAlertDescription.IllegalParameter, TlsMessages.UnexpectedCertificateContext);
                ClientHandshake.ValidateServerCertificate(Engine, certificate);
                Engine.Transcript.Add(message.Raw);
                _state = State.WaitCertificateVerify;
                break;
            case (State.WaitCertificateVerify, HandshakeType.CertificateVerify):
                OnCertificateVerify(message);
                break;
            case (State.WaitFinished, HandshakeType.Finished):
                OnServerFinished(message);
                break;
            default:
                throw Unexpected(message);
        }
    }

    /// <summary>
    /// RFC 8446 4.3.1: the server may only answer extensions we sent. ALPN must name exactly one protocol from our
    /// list; record_size_limit caps the records we send.
    /// </summary>
    private void OnEncryptedExtensions(HandshakeMessage message)
    {
        var extensions = SimpleMessages.ParseEncryptedExtensions(message.Body);
        foreach (var extension in extensions)
            Require(_hello.Extensions.Has(extension.Type), TlsAlertDescription.UnsupportedExtension, TlsMessages.ExtensionNotOffered);
        if (extensions.Find(ExtensionType.ApplicationLayerProtocolNegotiation) is { } alpn)
        {
            var offered = AlpnExtension.Parse(_hello.Extensions.Find(ExtensionType.ApplicationLayerProtocolNegotiation)!);
            var selected = AlpnExtension.Parse(alpn);
            Require(selected is [{ } protocol] && offered.Contains(protocol), TlsAlertDescription.IllegalParameter, TlsMessages.ProtocolNotOffered);
            Engine.ApplicationProtocol = selected[0];
        }
        if (extensions.Find(ExtensionType.RecordSizeLimit) is { } limit)
            ApplyPeerRecordSizeLimit(SimpleExtensions.ParseRecordSizeLimit(limit));
        Engine.Transcript.Add(message.Raw);
        _state = State.WaitCertificateOrRequest;
    }

    /// <summary>RFC 8446 4.4.3: the signature must use a scheme we offered and cover ClientHello..Certificate.</summary>
    private void OnCertificateVerify(HandshakeMessage message)
    {
        var signed = DigitallySigned.ParseCertificateVerify(message.Body);
        var offered = CodePointListExtension.Parse<TlsSignatureScheme>(_hello.Extensions.Find(ExtensionType.SignatureAlgorithms) ?? []);
        Require(offered.Contains(signed.Scheme), TlsAlertDescription.IllegalParameter, TlsMessages.SchemeNotOffered);
        var content = TlsSignatures.Tls13SignedContent(server: true, TranscriptHash());
        Require(TlsSignatures.Verify(signed.Scheme, Engine.PeerCertificate!, content, signed.Signature, TlsVersion.Tls13),
            TlsAlertDescription.DecryptError, TlsMessages.SignatureInvalid);
        Engine.SignatureScheme = signed.Scheme;
        Engine.Transcript.Add(message.Raw);
        _state = State.WaitFinished;
    }

    /// <summary>
    /// Verifies the server's Finished, installs the application read keys, then sends our (empty) Certificate if
    /// asked, the compatibility ChangeCipherSpec, and our Finished, and installs the application write keys.
    /// </summary>
    private void OnServerFinished(HandshakeMessage message)
    {
        Require(CryptographicOperations.FixedTimeEquals(message.Body, FinishedVerifyData(ServerHandshakeSecret!)),
            TlsAlertDescription.DecryptError, TlsMessages.FinishedMismatch);
        Engine.Transcript.Add(message.Raw);
        DeriveApplicationSecrets();
        Engine.SetReadProtection(Protection(ServerApplicationSecret!));
        Engine.EnableApplicationData();

        if (_hello.LegacySessionId.Length > 0) Engine.SendCompatibilityChangeCipherSpec();
        if (_certificateRequestContext is { } context)
            Engine.SendHandshake(new CertificateMessage { RequestContext = context, Certificates = [] }.Serialize(TlsVersion.Tls13));
        Engine.SendHandshake(SimpleMessages.Finished(FinishedVerifyData(ClientHandshakeSecret!)));
        Engine.SetWriteProtection(Protection(ClientApplicationSecret!));
        _state = State.Connected;
        Engine.CompleteHandshake();
    }
}
