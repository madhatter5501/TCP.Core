using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake.Messages;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The server's first step: read the ClientHello, pick the version and cipher suite, and hand over to the
/// version's own state machine.
/// </summary>
/// <remarks>
/// <para>
/// Version negotiation (RFC 8446 4.2.1): a client that lists supported_versions gets the highest listed version
/// we enable, and its legacy_version is ignored. A client without the extension is a TLS 1.2-or-older client whose
/// legacy_version is its real maximum.
/// </para>
/// <para>
/// The server chooses by its own preference among what the client offers. That is common practice, and it lets a
/// server keep strong suites first even when clients list weaker ones first.
/// </para>
/// </remarks>
internal sealed class ServerHandshake(TlsEngine engine) : HandshakeProtocol(engine)
{
    /// <summary>TLS_FALLBACK_SCSV (RFC 7507): the client is retrying with a lower version than it supports.</summary>
    private const ushort FallbackSignalingSuite = 0x5600;

    private TlsServerOptions ServerOptions => (TlsServerOptions)Options;

    /// <inheritdoc/>
    public override void OnMessage(HandshakeMessage message)
    {
        if (message.Type != HandshakeType.ClientHello) throw Unexpected(message);
        var hello = ClientHello.Parse(message.Body);
        Engine.ClientHelloExchanged = true;
        var version = NegotiateVersion(hello);
        // RFC 7507: a fallback retry means an earlier attempt at a higher version failed, perhaps by attack.
        Require(!hello.CipherSuites.Contains(FallbackSignalingSuite) || version == Options.MaximumVersion,
            TlsAlertDescription.InappropriateFallback, TlsMessages.InappropriateFallback);
        var signer = SignerFor(ServerOptions);
        var suite = Options.CipherSuites.Select(CipherSuiteInfo.Get).FirstOrDefault(info =>
            info.Version == version && hello.CipherSuites.Contains((ushort)info.Suite) &&
            (info.Authentication == ServerAuthentication.Any || info.Authentication == signer.KeyType));
        Require(suite is not null, TlsAlertDescription.HandshakeFailure, TlsMessages.NoCommonCipherSuite);
        Engine.Version = version;
        Engine.Suite = suite;
        if (version == TlsVersion.Tls13)
        {
            var next = new Tls13ServerHandshake(Engine, suite!, signer);
            Engine.SwitchProtocol(next);
            next.Start(hello, message);
        }
        else
        {
            var next = new Tls12ServerHandshake(Engine, suite!, signer);
            Engine.SwitchProtocol(next);
            next.Start(hello, message);
        }
    }

    /// <summary>The server's signer: the test override, or the certificate's private key.</summary>
    internal static TlsSigner SignerFor(TlsServerOptions options) => options.Signer ?? TlsSigner.ForCertificate(options.Certificate);

    /// <summary>
    /// RFC 7301 3.2: the first of our protocols the client also offered. If both sides use ALPN but share no
    /// protocol, the handshake fails with no_application_protocol rather than silently speaking the wrong one.
    /// </summary>
    internal static string? SelectApplicationProtocol(TlsOptions options, ClientHello hello)
    {
        if (hello.Extensions.Find(ExtensionType.ApplicationLayerProtocolNegotiation) is not { } data ||
            options.ApplicationProtocols.Count == 0) return null;
        var offered = AlpnExtension.Parse(data);
        return options.ApplicationProtocols.FirstOrDefault(offered.Contains)
            ?? throw new TlsAlertException(TlsAlertDescription.NoApplicationProtocol, TlsMessages.NoCommonApplicationProtocol);
    }

    /// <summary>The Server Name Indication, if the client sent one.</summary>
    internal static string? ServerNameOf(ClientHello hello) =>
        hello.Extensions.Find(ExtensionType.ServerName) is { } data ? ServerNameExtension.Parse(data) : null;

    /// <summary>The signature scheme to use: our best that the client accepts, or handshake_failure.</summary>
    internal static TlsSignatureScheme ChooseSignatureScheme(TlsSigner signer, TlsVersion version, ClientHello hello)
    {
        var data = hello.Extensions.Find(ExtensionType.SignatureAlgorithms)
            ?? throw new TlsAlertException(version == TlsVersion.Tls13 ? TlsAlertDescription.MissingExtension : TlsAlertDescription.HandshakeFailure,
                TlsMessages.MissingSignatureAlgorithms);
        var offered = CodePointListExtension.Parse<TlsSignatureScheme>(data);
        foreach (var scheme in signer.Schemes(version))
            if (offered.Contains(scheme)) return scheme;
        throw new TlsAlertException(TlsAlertDescription.HandshakeFailure, TlsMessages.NoCommonSignatureScheme);
    }

    /// <summary>RFC 8446 4.2.1 and RFC 5246 E.1: the version both sides support.</summary>
    private TlsVersion NegotiateVersion(ClientHello hello)
    {
        if (hello.Extensions.Find(ExtensionType.SupportedVersions) is { } data)
        {
            var offered = SupportedVersionsExtension.ParseClient(data);
            foreach (var version in (TlsVersion[])[TlsVersion.Tls13, TlsVersion.Tls12])
                if (Options.Enables(version) && offered.Contains((ushort)version)) return version;
            throw new TlsAlertException(TlsAlertDescription.ProtocolVersion, TlsMessages.NoCommonVersion);
        }
        Require(hello.LegacyVersion >= (ushort)TlsVersion.Tls12 && Options.Enables(TlsVersion.Tls12),
            TlsAlertDescription.ProtocolVersion, TlsMessages.NoCommonVersion);
        return TlsVersion.Tls12;
    }
}
