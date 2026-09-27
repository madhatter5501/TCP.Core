using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// The first message of every handshake: everything the client supports, plus (TLS 1.3) key shares for the
/// groups it guesses the server will pick.
/// </summary>
/// <remarks>
/// <code>
/// struct {
///     ProtocolVersion legacy_version = 0x0303;     // TLS 1.2; the real versions are in supported_versions
///     Random random;                               // 32 bytes from a secure random generator
///     opaque legacy_session_id&lt;0..32&gt;;           // TLS 1.2 resumption; TLS 1.3 sends random bytes (D.4)
///     CipherSuite cipher_suites&lt;2..2^16-2&gt;;
///     opaque legacy_compression_methods&lt;1..2^8-1&gt;; // exactly [0], "null": TLS compression is dead (CRIME)
///     Extension extensions&lt;8..2^16-1&gt;;
/// } ClientHello;                                   // RFC 8446 4.1.2
/// </code>
/// Cipher suites stay raw numbers so the ones we do not know (including GREASE values, RFC 8701) survive.
/// </remarks>
internal sealed class ClientHello
{
    /// <summary>Both hello randoms are 32 bytes.</summary>
    public const int RandomLength = 32;
    /// <summary>Longest legacy_session_id.</summary>
    public const int MaximumSessionIdLength = 32;
    /// <summary>The "null" compression method, the only one TLS 1.3 allows.</summary>
    public const byte NullCompression = 0;

    /// <summary>Frozen at 0x0303 by TLS 1.3; a TLS 1.2-only client's real maximum version.</summary>
    public ushort LegacyVersion { get; init; } = (ushort)TlsVersion.Tls12;

    /// <summary>Client randomness, mixed into every key.</summary>
    public required byte[] Random { get; init; }

    /// <summary>Session to resume in TLS 1.2; 32 random bytes to trigger middlebox compatibility mode in TLS 1.3.</summary>
    public byte[] LegacySessionId { get; init; } = [];

    /// <summary>Offered cipher suite code points, most preferred first.</summary>
    public required List<ushort> CipherSuites { get; init; }

    /// <summary>Offered compression methods; must contain null.</summary>
    public byte[] CompressionMethods { get; init; } = [NullCompression];

    /// <summary>Extensions in the order sent.</summary>
    public List<TlsExtension> Extensions { get; init; } = [];

    /// <summary>The framed handshake message.</summary>
    public byte[] Serialize()
    {
        var writer = new TlsWriter();
        writer.WriteUInt16(LegacyVersion);
        writer.WriteBytes(Random);
        writer.WriteVector8(LegacySessionId);
        using (writer.OpenVector(2))
            foreach (var suite in CipherSuites) writer.WriteUInt16(suite);
        writer.WriteVector8(CompressionMethods);
        TlsExtension.WriteList(writer, Extensions);
        return HandshakeMessage.Frame(HandshakeType.ClientHello, writer.WrittenSpan);
    }

    /// <summary>Parses a ClientHello body.</summary>
    public static ClientHello Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var version = reader.ReadUInt16();
        var random = reader.ReadBytes(RandomLength).ToArray();
        var sessionId = reader.ReadVector8();
        if (sessionId.Length > MaximumSessionIdLength)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.SessionIdTooLong);
        var suiteBytes = new TlsReader(reader.ReadVector16());
        if (suiteBytes.IsEmpty || suiteBytes.Remaining % sizeof(ushort) != 0)
            throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        var suites = new List<ushort>();
        while (!suiteBytes.IsEmpty) suites.Add(suiteBytes.ReadUInt16());
        var compression = reader.ReadVector8();
        if (compression.IsEmpty) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        // A TLS 1.2 ClientHello may end here; the extensions field is optional there (RFC 5246 7.4.1.2).
        var extensions = reader.IsEmpty ? [] : TlsExtension.ParseList(reader.ReadVector16());
        reader.EnsureEnd();
        return new ClientHello
        {
            LegacyVersion = version, Random = random, LegacySessionId = [.. sessionId], CipherSuites = suites,
            CompressionMethods = [.. compression], Extensions = extensions,
        };
    }
}
