using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The client's first step: send one ClientHello that works for both TLS 1.3 and TLS 1.2 servers, then read the
/// ServerHello to learn which version the server chose, and hand over to that version's state machine.
/// </summary>
/// <remarks>
/// <para>
/// A TLS 1.3 server answers with supported_versions = 0x0304 and its key share. A TLS 1.2 server ignores the
/// TLS 1.3 extensions and answers in the TLS 1.2 style. A TLS 1.3 server may instead send a HelloRetryRequest,
/// in which case we send a second ClientHello with a key share for the group it asked for (RFC 8446 4.1.4).
/// </para>
/// <para>
/// Downgrade protection (RFC 8446 4.1.3): if we offered TLS 1.3 but got TLS 1.2, the server random must not end
/// with the "DOWNGRD" marker, which a genuine TLS 1.3 server puts there when it negotiates TLS 1.2 itself. Seeing
/// it means someone removed our TLS 1.3 offer in transit.
/// </para>
/// </remarks>
internal sealed class ClientHandshake(TlsEngine engine) : HandshakeProtocol(engine)
{
    private const int CompatibilitySessionIdLength = 32;
    private const int DowngradeSentinelOffset = ClientHello.RandomLength - 8;

    private ClientHello? _hello;
    private TlsKeyExchange? _keyExchange;
    private CipherSuiteInfo? _retrySuite;

    private TlsClientOptions ClientOptions => (TlsClientOptions)Options;

    /// <summary>Builds and sends the ClientHello.</summary>
    public void Start()
    {
        if (ClientOptions.ClientHelloOverride is { } raw)
        {
            _hello = ClientHello.Parse(raw.AsSpan(HandshakeMessage.HeaderLength));
            if (_hello.Extensions.Find(ExtensionType.KeyShare) is { } shares &&
                KeyShareExtension.ParseClient(shares) is [{ } first, ..])
                _keyExchange = Options.KeyExchangeFactory(first.Group);
        }
        else
        {
            _hello = Build();
        }
        Engine.ServerName = ClientOptions.TargetHost;
        // RFC 8446 5.1: the first ClientHello's record may say TLS 1.0 for the benefit of old servers.
        Engine.Records.WriteVersion = (ushort)TlsVersion.Tls10;
        Engine.SendHandshake(_hello.Serialize());
        Engine.Records.FlushHandshake();
        Engine.Records.WriteVersion = (ushort)TlsVersion.Tls12;
        Engine.ClientHelloExchanged = true;
    }

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        if (message.Type != HandshakeType.ServerHello) throw Unexpected(message);
        var serverHello = ServerHello.Parse(message.Body);
        if (serverHello.IsHelloRetryRequest)
        {
            OnHelloRetryRequest(serverHello, message);
            return;
        }
        var version = NegotiatedVersion(serverHello);
        var suite = CipherSuiteInfo.Find(serverHello.CipherSuite);
        Require(suite is not null && suite.Version == version && _hello!.CipherSuites.Contains(serverHello.CipherSuite) &&
                (_retrySuite is null || _retrySuite == suite),
            TlsAlertDescription.IllegalParameter, TlsMessages.CipherSuiteNotOffered);
        Require(serverHello.CompressionMethod == ClientHello.NullCompression, TlsAlertDescription.IllegalParameter, TlsMessages.CompressionOffered);
        Engine.Version = version;
        Engine.Suite = suite;
        Engine.Transcript.Add(message.Raw);
        if (version == TlsVersion.Tls13)
        {
            Require(serverHello.LegacySessionId.AsSpan().SequenceEqual(_hello!.LegacySessionId),
                TlsAlertDescription.IllegalParameter, TlsMessages.SessionIdMismatch);
            var shareData = serverHello.Extensions.Find(ExtensionType.KeyShare);
            Require(shareData is not null, TlsAlertDescription.MissingExtension, TlsMessages.MissingKeyShare);
            var share = KeyShareExtension.ParseServer(shareData!);
            Require(_keyExchange is not null && share.Group == _keyExchange.Group, TlsAlertDescription.IllegalParameter, TlsMessages.WrongKeyShareGroup);
            var sharedSecret = _keyExchange!.DeriveSharedSecret(share.KeyExchange);
            Engine.Group = share.Group;
            Engine.SwitchProtocol(new Tls13ClientHandshake(Engine, suite!, _hello, sharedSecret));
        }
        else
        {
            Engine.SwitchProtocol(new Tls12ClientHandshake(Engine, suite!, _hello!, serverHello));
        }
        _keyExchange?.Dispose();
    }

    /// <summary>
    /// Checks the server's certificate chain with the configured validation, or the default of a trusted chain and a
    /// matching host name. Shared by both versions' client state machines.
    /// </summary>
    internal static X509Certificate2 ValidateServerCertificate(TlsEngine engine, CertificateMessage message)
    {
        // RFC 8446 4.4.2.4: a server must send a certificate; an empty list is a decode_error.
        if (message.Certificates.Count == 0) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.EmptyCertificate);
        X509Certificate2 leaf;
        var chain = new X509Certificate2Collection();
        try
        {
            leaf = X509CertificateLoader.LoadCertificate(message.Certificates[0]);
            foreach (var der in message.Certificates.Skip(1)) chain.Add(X509CertificateLoader.LoadCertificate(der));
        }
        catch (CryptographicException)
        {
            throw new TlsAlertException(TlsAlertDescription.BadCertificate, TlsMessages.CertificateUnreadable);
        }
        var options = (TlsClientOptions)engine.Options;
        var trusted = options.CertificateValidation?.Invoke(leaf, chain)
            ?? TlsCertificates.ValidateServerCertificate(leaf, chain, options.TargetHost);
        if (!trusted) throw new TlsAlertException(TlsAlertDescription.BadCertificate, TlsMessages.CertificateRejected);
        engine.PeerCertificate = leaf;
        return leaf;
    }

    /// <summary>
    /// The ClientHello: every enabled version and suite, key share for the preferred group (TLS 1.3), and the
    /// TLS 1.2 extensions (point formats, extended master secret, renegotiation_info).
    /// </summary>
    private ClientHello Build()
    {
        var tls13 = Options.Enables(TlsVersion.Tls13);
        var tls12 = Options.Enables(TlsVersion.Tls12);
        var suites = Options.CipherSuites.Select(CipherSuiteInfo.Get).Where(info => Options.Enables(info.Version));
        List<TlsExtension> extensions = [];
        if (ServerNameExtension.ForClient(ClientOptions.TargetHost) is { } serverName) extensions.Add(serverName);
        extensions.Add(CodePointListExtension.Create(ExtensionType.SupportedGroups, Options.Groups));
        extensions.Add(CodePointListExtension.Create(ExtensionType.SignatureAlgorithms, TlsSignatures.DefaultOffered));
        if (Options.ApplicationProtocols.Count > 0) extensions.Add(AlpnExtension.Create(Options.ApplicationProtocols));
        if (tls12)
        {
            extensions.Add(SimpleExtensions.UncompressedPointFormats);
            extensions.Add(SimpleExtensions.ExtendedMasterSecret);
            extensions.Add(SimpleExtensions.InitialRenegotiationInfo);
        }
        if (tls13)
        {
            TlsVersion[] versions = tls12 ? [TlsVersion.Tls13, TlsVersion.Tls12] : [TlsVersion.Tls13];
            extensions.Add(SupportedVersionsExtension.ForClient(versions));
            _keyExchange = Options.KeyExchangeFactory(Options.Groups[0])
                ?? throw new InvalidOperationException(TlsMessages.NoCommonGroup);
            extensions.Add(KeyShareExtension.ForClient([new KeyShareEntry(_keyExchange.Group, _keyExchange.PublicKey)]));
        }
        var sessionId = new byte[tls13 && ClientOptions.MiddleboxCompatibility ? CompatibilitySessionIdLength : 0];
        Options.FillRandom(sessionId);
        return new ClientHello
        {
            Random = NewRandom(), LegacySessionId = sessionId, CipherSuites = [.. suites.Select(info => (ushort)info.Suite)],
            Extensions = extensions,
        };
    }

    /// <summary>RFC 8446 4.1.3-4.1.4 and 4.2.1: which version the ServerHello selected, with downgrade checks.</summary>
    private TlsVersion NegotiatedVersion(ServerHello serverHello)
    {
        if (serverHello.Extensions.Find(ExtensionType.SupportedVersions) is { } data)
        {
            Require(SupportedVersionsExtension.ParseServer(data) == (ushort)TlsVersion.Tls13 && Options.Enables(TlsVersion.Tls13) &&
                    serverHello.LegacyVersion == (ushort)TlsVersion.Tls12,
                TlsAlertDescription.IllegalParameter, TlsMessages.VersionNotOffered);
            return TlsVersion.Tls13;
        }
        Require(serverHello.LegacyVersion == (ushort)TlsVersion.Tls12 && Options.Enables(TlsVersion.Tls12),
            TlsAlertDescription.ProtocolVersion, TlsMessages.NoCommonVersion);
        if (Options.Enables(TlsVersion.Tls13))
        {
            var tail = serverHello.Random.AsSpan(DowngradeSentinelOffset);
            Require(!tail.SequenceEqual(ServerHello.Tls12DowngradeSentinel) && !tail.SequenceEqual(ServerHello.Tls11DowngradeSentinel),
                TlsAlertDescription.IllegalParameter, TlsMessages.DowngradeDetected);
        }
        return TlsVersion.Tls12;
    }

    /// <summary>
    /// RFC 8446 4.1.4: the server wants a key share in another group (and may send a cookie to echo). Only one
    /// retry is allowed, and it must actually change something.
    /// </summary>
    private void OnHelloRetryRequest(ServerHello retry, HandshakeMessage message)
    {
        Require(_retrySuite is null, TlsAlertDescription.UnexpectedMessage, TlsMessages.SecondHelloRetry);
        Require(retry.Extensions.Find(ExtensionType.SupportedVersions) is { } version &&
                SupportedVersionsExtension.ParseServer(version) == (ushort)TlsVersion.Tls13 && Options.Enables(TlsVersion.Tls13),
            TlsAlertDescription.IllegalParameter, TlsMessages.VersionNotOffered);
        var suite = CipherSuiteInfo.Find(retry.CipherSuite);
        Require(suite is { Version: TlsVersion.Tls13 } && _hello!.CipherSuites.Contains(retry.CipherSuite),
            TlsAlertDescription.IllegalParameter, TlsMessages.CipherSuiteNotOffered);
        Require(retry.LegacySessionId.AsSpan().SequenceEqual(_hello!.LegacySessionId), TlsAlertDescription.IllegalParameter, TlsMessages.SessionIdMismatch);

        List<TlsExtension> extensions = [.. _hello.Extensions.Where(e => e.Type is not (ExtensionType.EarlyData or ExtensionType.Cookie))];
        if (retry.Extensions.Find(ExtensionType.KeyShare) is { } groupData)
        {
            var group = KeyShareExtension.ParseRetry(groupData);
            var offered = CodePointListExtension.Parse<TlsNamedGroup>(_hello.Extensions.Find(ExtensionType.SupportedGroups) ?? []);
            Require(offered.Contains(group) && group != _keyExchange?.Group, TlsAlertDescription.IllegalParameter, TlsMessages.WrongKeyShareGroup);
            _keyExchange?.Dispose();
            _keyExchange = Options.KeyExchangeFactory(group)
                ?? throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.WrongKeyShareGroup);
            var index = extensions.FindIndex(e => e.Type == ExtensionType.KeyShare);
            extensions[index] = KeyShareExtension.ForClient([new KeyShareEntry(group, _keyExchange.PublicKey)]);
        }
        if (retry.Extensions.Find(ExtensionType.Cookie) is { } cookie)
        {
            SimpleExtensions.ParseCookie(cookie);
            var index = extensions.FindIndex(e => e.Type == ExtensionType.KeyShare) + 1;
            extensions.Insert(index, new TlsExtension(ExtensionType.Cookie, cookie));
        }

        _retrySuite = suite;
        Engine.HelloRetryRequested = true;
        Engine.Transcript.ReplaceWithMessageHash(suite!.Hash);
        Engine.Transcript.Add(message.Raw);
        if (_hello.LegacySessionId.Length > 0) Engine.SendCompatibilityChangeCipherSpec();
        _hello = new ClientHello
        {
            LegacyVersion = _hello.LegacyVersion, Random = _hello.Random, LegacySessionId = _hello.LegacySessionId,
            CipherSuites = _hello.CipherSuites, CompressionMethods = _hello.CompressionMethods, Extensions = extensions,
        };
        Engine.SendHandshake(_hello.Serialize());
    }
}
