using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The TLS 1.3 server handshake (RFC 8446 2, 4): one round trip from ClientHello to application data.
/// </summary>
/// <remarks>
/// <code>
///        Client                                           Server
///        ClientHello + key_share          --------&gt;
///                                                    ServerHello + key_share
///                                                  {EncryptedExtensions}
///                                                  {Certificate}
///                                                  {CertificateVerify}
///                                         &lt;--------   {Finished}
///        {Finished}                       --------&gt;
///        [Application Data]               &lt;-------&gt;  [Application Data]
///
///  {} handshake traffic keys    [] application traffic keys
/// </code>
/// If the client's key shares are all for groups we do not use, but it lists one we do in supported_groups, we
/// first send a HelloRetryRequest naming that group and wait for a second ClientHello (RFC 8446 4.1.4).
/// </remarks>
internal sealed class Tls13ServerHandshake(TlsEngine engine, CipherSuiteInfo suite, TlsSigner signer) : Tls13Handshake(engine, suite)
{
    /// <summary>RFC 8449: with no limit of our own we accept full records; in TLS 1.3 the value counts the content type byte.</summary>
    private const int OwnRecordSizeLimit = TlsRecord.MaximumPlaintextLength + 1;

    private enum State { WaitClientHello2, WaitFinished, Connected }

    private State _state;
    private ClientHello? _firstHello;
    private TlsNamedGroup _retryGroup;

    private TlsServerOptions ServerOptions => (TlsServerOptions)Options;

    /// <summary>Processes the first ClientHello: answer it, or ask for a different key share.</summary>
    public void Start(ClientHello hello, HandshakeMessage message)
    {
        Engine.Transcript.Add(message.Raw);
        Require(hello.CompressionMethods is [ClientHello.NullCompression], TlsAlertDescription.IllegalParameter, TlsMessages.CompressionOffered);
        // RFC 8446 9.2: without a pre-shared key, supported_groups and key_share are both mandatory.
        var groupsData = hello.Extensions.Find(ExtensionType.SupportedGroups);
        var sharesData = hello.Extensions.Find(ExtensionType.KeyShare);
        Require(groupsData is not null && sharesData is not null, TlsAlertDescription.MissingExtension, TlsMessages.MissingKeyShare);
        var groups = CodePointListExtension.Parse<TlsNamedGroup>(groupsData!);
        var shares = KeyShareExtension.ParseClient(sharesData!);
        foreach (var group in Options.Groups)
        {
            if (shares.FirstOrDefault(s => s.Group == group) is { KeyExchange: not null } share)
            {
                Respond(hello, share);
                return;
            }
        }
        var retryGroup = Options.Groups.FirstOrDefault(groups.Contains);
        Require(retryGroup != default, TlsAlertDescription.HandshakeFailure, TlsMessages.NoCommonGroup);
        SendHelloRetryRequest(hello, retryGroup);
    }

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        switch (_state, message.Type)
        {
            case (State.WaitClientHello2, HandshakeType.ClientHello):
                OnSecondClientHello(message);
                break;
            case (State.WaitFinished, HandshakeType.Finished):
                OnClientFinished(message);
                break;
            default:
                throw Unexpected(message);
        }
    }

    /// <summary>
    /// RFC 8446 4.1.4: a ServerHello with the special HelloRetryRequest random and a key_share naming the group we
    /// want. ClientHello1 is replaced in the transcript by its hash, so the retry is bound to the first attempt.
    /// </summary>
    private void SendHelloRetryRequest(ClientHello hello, TlsNamedGroup group)
    {
        _firstHello = hello;
        _retryGroup = group;
        Engine.HelloRetryRequested = true;
        Engine.Transcript.ReplaceWithMessageHash(Suite.Hash);
        var retry = new ServerHello
        {
            Random = ServerHello.HelloRetryRequestRandom, LegacySessionId = hello.LegacySessionId, CipherSuite = (ushort)Suite.Suite,
            Extensions = [KeyShareExtension.ForRetry(group), SupportedVersionsExtension.ForServer(TlsVersion.Tls13)],
        };
        Engine.SendHandshake(retry.Serialize());
        if (hello.LegacySessionId.Length > 0) Engine.SendCompatibilityChangeCipherSpec();
        _state = State.WaitClientHello2;
    }

    /// <summary>
    /// The retried ClientHello must match the first apart from the key share (RFC 8446 4.1.2), and must now carry
    /// exactly one share, for the group we asked for.
    /// </summary>
    private void OnSecondClientHello(HandshakeMessage message)
    {
        var hello = ClientHello.Parse(message.Body);
        Require(hello.CipherSuites.Contains((ushort)Suite.Suite) && hello.LegacySessionId.AsSpan().SequenceEqual(_firstHello!.LegacySessionId),
            TlsAlertDescription.IllegalParameter, TlsMessages.RetryChangedHello);
        var sharesData = hello.Extensions.Find(ExtensionType.KeyShare);
        Require(sharesData is not null, TlsAlertDescription.MissingExtension, TlsMessages.MissingKeyShare);
        var shares = KeyShareExtension.ParseClient(sharesData!);
        Require(shares is [{ } only] && only.Group == _retryGroup, TlsAlertDescription.IllegalParameter, TlsMessages.RetryWrongKeyShare);
        Engine.Transcript.Add(message.Raw);
        Respond(hello, shares[0]);
    }

    /// <summary>
    /// Sends ServerHello, installs the handshake keys, then sends EncryptedExtensions, Certificate,
    /// CertificateVerify and Finished in one encrypted flight, and installs the application write keys.
    /// </summary>
    private void Respond(ClientHello hello, KeyShareEntry clientShare)
    {
        var scheme = ServerHandshake.ChooseSignatureScheme(signer, TlsVersion.Tls13, hello);
        var protocol = ServerHandshake.SelectApplicationProtocol(Options, hello);
        var serverName = ServerHandshake.ServerNameOf(hello);
        var recordSizeLimit = hello.Extensions.Find(ExtensionType.RecordSizeLimit) is { } limitData
            ? SimpleExtensions.ParseRecordSizeLimit(limitData) : (int?)null;

        using var keyExchange = Options.KeyExchangeFactory(clientShare.Group)
            ?? throw new TlsAlertException(TlsAlertDescription.InternalError, TlsMessages.NoCommonGroup);
        var sharedSecret = keyExchange.DeriveSharedSecret(clientShare.KeyExchange);
        var serverHello = new ServerHello
        {
            Random = NewRandom(), LegacySessionId = hello.LegacySessionId, CipherSuite = (ushort)Suite.Suite,
            Extensions =
            [
                KeyShareExtension.ForServer(new KeyShareEntry(clientShare.Group, keyExchange.PublicKey)),
                SupportedVersionsExtension.ForServer(TlsVersion.Tls13),
            ],
        };
        Engine.SendHandshake(serverHello.Serialize());
        if (hello.LegacySessionId.Length > 0) Engine.SendCompatibilityChangeCipherSpec();

        DeriveHandshakeSecrets(sharedSecret);
        Engine.SetWriteProtection(Protection(ServerHandshakeSecret!));
        Engine.SetReadProtection(Protection(ClientHandshakeSecret!));
        Engine.Records.AcceptPlaintextAlerts = true;
        if (recordSizeLimit is { } limit) ApplyPeerRecordSizeLimit(limit);

        List<TlsExtension> encryptedExtensions = [.. ServerOptions.AdditionalEncryptedExtensions];
        if (recordSizeLimit is not null) encryptedExtensions.Add(SimpleExtensions.RecordSizeLimit(OwnRecordSizeLimit));
        if (serverName is not null) encryptedExtensions.Add(ServerNameExtension.Acknowledgment);
        if (protocol is not null) encryptedExtensions.Add(AlpnExtension.Create([protocol]));
        Engine.SendHandshake(SimpleMessages.EncryptedExtensions(encryptedExtensions));

        Engine.SendHandshake(new CertificateMessage { Certificates = CertificateChain() }.Serialize(TlsVersion.Tls13));
        var signedContent = TlsSignatures.Tls13SignedContent(server: true, TranscriptHash()); // ClientHello..Certificate
        Engine.SendHandshake(new DigitallySigned(scheme, signer.Sign(scheme, signedContent)).SerializeCertificateVerify());
        Engine.SendHandshake(SimpleMessages.Finished(FinishedVerifyData(ServerHandshakeSecret!)));

        DeriveApplicationSecrets();
        Engine.SetWriteProtection(Protection(ServerApplicationSecret!)); // Flushes the flight under the handshake keys first.
        Engine.Group = clientShare.Group;
        Engine.SignatureScheme = scheme;
        Engine.ApplicationProtocol = protocol;
        Engine.ServerName = serverName;
        _state = State.WaitFinished;
    }

    /// <summary>
    /// The client's Finished proves it derived the same handshake keys from the same transcript; only then does the
    /// server trust anything the client sends under the application keys.
    /// </summary>
    private void OnClientFinished(HandshakeMessage message)
    {
        Require(CryptographicOperations.FixedTimeEquals(message.Body, FinishedVerifyData(ClientHandshakeSecret!)),
            TlsAlertDescription.DecryptError, TlsMessages.FinishedMismatch);
        Engine.Transcript.Add(message.Raw);
        Engine.SetReadProtection(Protection(ClientApplicationSecret!));
        Engine.EnableApplicationData();
        _state = State.Connected;
        Engine.CompleteHandshake();
    }

    /// <summary>DER certificates to send: ours, then any intermediates.</summary>
    private List<byte[]> CertificateChain() =>
        [ServerOptions.Certificate.RawData, .. (ServerOptions.CertificateChain ?? []).Select(c => c.RawData)];
}
