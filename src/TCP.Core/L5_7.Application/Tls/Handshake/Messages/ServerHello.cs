using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// The server's answer to ClientHello: the version, cipher suite and parameters it chose. In TLS 1.3 the same
/// structure, with a special random, is a HelloRetryRequest.
/// </summary>
/// <remarks>
/// <code>
/// struct {
///     ProtocolVersion legacy_version = 0x0303;
///     Random random;
///     opaque legacy_session_id_echo&lt;0..32&gt;;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions&lt;6..2^16-1&gt;;
/// } ServerHello;                                   // RFC 8446 4.1.3
/// </code>
/// </remarks>
internal sealed class ServerHello
{
    /// <summary>
    /// RFC 8446 4.1.3: a ServerHello whose random is SHA-256("HelloRetryRequest") is a HelloRetryRequest. Reusing
    /// the ServerHello type keeps TLS 1.2 middleboxes from seeing an unknown message.
    /// </summary>
    public static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    /// <summary>
    /// RFC 8446 4.1.3: a TLS 1.3-capable server that negotiates TLS 1.2 ends its random with "DOWNGRD" and 0x01.
    /// A TLS 1.3 client that sees it knows an attacker stripped its supported_versions offer, and aborts. The
    /// signature covers the random, so the attacker cannot remove the marker.
    /// </summary>
    public static readonly byte[] Tls12DowngradeSentinel = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

    /// <summary>The TLS 1.1-and-below variant of the downgrade marker.</summary>
    public static readonly byte[] Tls11DowngradeSentinel = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

    /// <summary>0x0303; in TLS 1.2 the negotiated version itself.</summary>
    public ushort LegacyVersion { get; init; } = (ushort)TlsVersion.Tls12;

    /// <summary>Server randomness, or <see cref="HelloRetryRequestRandom"/>.</summary>
    public required byte[] Random { get; init; }

    /// <summary>TLS 1.3 echoes the client's legacy_session_id; TLS 1.2 names the session (empty: not resumable).</summary>
    public byte[] LegacySessionId { get; init; } = [];

    /// <summary>The chosen cipher suite code point.</summary>
    public required ushort CipherSuite { get; init; }

    /// <summary>Always 0.</summary>
    public byte CompressionMethod { get; init; } = ClientHello.NullCompression;

    /// <summary>Extensions in the order sent.</summary>
    public List<TlsExtension> Extensions { get; init; } = [];

    /// <summary>This is a HelloRetryRequest rather than a real ServerHello.</summary>
    public bool IsHelloRetryRequest => Random.AsSpan().SequenceEqual(HelloRetryRequestRandom);

    /// <summary>The framed handshake message.</summary>
    public byte[] Serialize()
    {
        var writer = new TlsWriter();
        writer.WriteUInt16(LegacyVersion);
        writer.WriteBytes(Random);
        writer.WriteVector8(LegacySessionId);
        writer.WriteUInt16(CipherSuite);
        writer.WriteUInt8(CompressionMethod);
        TlsExtension.WriteList(writer, Extensions);
        return HandshakeMessage.Frame(HandshakeType.ServerHello, writer.WrittenSpan);
    }

    /// <summary>Parses a ServerHello body.</summary>
    public static ServerHello Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var version = reader.ReadUInt16();
        var random = reader.ReadBytes(ClientHello.RandomLength).ToArray();
        var sessionId = reader.ReadVector8();
        if (sessionId.Length > ClientHello.MaximumSessionIdLength)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.SessionIdTooLong);
        var suite = reader.ReadUInt16();
        var compression = reader.ReadUInt8();
        var extensions = reader.IsEmpty ? [] : TlsExtension.ParseList(reader.ReadVector16());
        reader.EnsureEnd();
        return new ServerHello
        {
            LegacyVersion = version, Random = random, LegacySessionId = [.. sessionId], CipherSuite = suite,
            CompressionMethod = compression, Extensions = extensions,
        };
    }
}
