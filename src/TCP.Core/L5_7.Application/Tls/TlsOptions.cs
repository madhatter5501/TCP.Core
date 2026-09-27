using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Cryptography;

namespace TCP.L5_7.Application.Tls;

/// <summary>
/// Settings shared by both ends of a TLS connection: which versions, cipher suites, key exchange groups and
/// application protocols to offer or accept, most preferred first.
/// </summary>
/// <remarks>
/// A server picks from the client's offer by the server's own preference order, as RFC 8446 lets it. The internal
/// members are seams for tests that replay published traces: they replace randomness, key generation and signing,
/// which would otherwise make every handshake different.
/// </remarks>
public abstract record TlsOptions
{
    /// <summary>Lowest version to negotiate.</summary>
    public TlsVersion MinimumVersion { get; init; } = TlsVersion.Tls12;

    /// <summary>Highest version to negotiate.</summary>
    public TlsVersion MaximumVersion { get; init; } = TlsVersion.Tls13;

    /// <summary>
    /// Cipher suites in preference order. TLS 1.3 and TLS 1.2 suites can be mixed; each is used only with its own
    /// version. The default puts TLS_AES_128_GCM_SHA256 and TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 first.
    /// </summary>
    public IReadOnlyList<TlsCipherSuite> CipherSuites { get; init; } = [.. CipherSuiteInfo.All.Select(info => info.Suite)];

    /// <summary>Key exchange groups in preference order. A client sends its key share for the first one.</summary>
    public IReadOnlyList<TlsNamedGroup> Groups { get; init; } = [TlsNamedGroup.Secp256r1, TlsNamedGroup.Secp384r1];

    /// <summary>ALPN protocol names in preference order, such as "h2" and "http/1.1"; empty to skip ALPN.</summary>
    public IReadOnlyList<string> ApplicationProtocols { get; init; } = [];

    /// <summary>Fills hello randoms and session ids; tests supply fixed bytes.</summary>
    internal Action<Span<byte>> FillRandom { get; init; } = RandomNumberGenerator.Fill;

    /// <summary>Creates ephemeral key pairs; tests supply recorded ones.</summary>
    internal Func<TlsNamedGroup, TlsKeyExchange?> KeyExchangeFactory { get; init; } = TlsKeyExchange.Create;

    /// <summary><paramref name="version"/> lies between <see cref="MinimumVersion"/> and <see cref="MaximumVersion"/>.</summary>
    internal bool Enables(TlsVersion version) => version >= MinimumVersion && version <= MaximumVersion;
}
