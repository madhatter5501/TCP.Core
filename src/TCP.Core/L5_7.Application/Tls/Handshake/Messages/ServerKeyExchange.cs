using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// TLS 1.2 ECDHE ServerKeyExchange (RFC 8422 5.4): the server's ephemeral public key, signed with its certificate
/// key so the client knows the key really came from the server.
/// </summary>
/// <remarks>
/// <code>
/// enum { named_curve(3) } ECCurveType;
/// struct { ECCurveType curve_type; NamedCurve namedcurve; } ECParameters;
/// struct { ECParameters curve_params; opaque point&lt;1..2^8-1&gt;; } ServerECDHParams;
/// struct { ServerECDHParams params; digitally-signed signed_params; } ServerKeyExchange;
/// signed content = ClientHello.random + ServerHello.random + ServerECDHParams
/// </code>
/// Signing the randoms stops a replay of an old ServerKeyExchange; but only the randoms and this message are
/// signed, not the whole handshake, which is one of the weaknesses TLS 1.3's CertificateVerify fixes.
/// </remarks>
internal sealed class ServerKeyExchange
{
    private const byte NamedCurveType = 3;

    /// <summary>The curve of the ephemeral key.</summary>
    public required TlsNamedGroup Group { get; init; }

    /// <summary>The ephemeral public key.</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>The server's signature over the randoms and <see cref="EncodeParameters"/>.</summary>
    public required DigitallySigned Signed { get; init; }

    /// <summary>ServerECDHParams: curve_type, namedcurve and point.</summary>
    public static byte[] EncodeParameters(TlsNamedGroup group, byte[] publicKey)
    {
        var writer = new TlsWriter();
        writer.WriteUInt8(NamedCurveType);
        writer.WriteUInt16((ushort)group);
        writer.WriteVector8(publicKey);
        return writer.ToArray();
    }

    /// <summary>The bytes the server signs: client_random + server_random + params.</summary>
    public static byte[] SignedContent(byte[] clientRandom, byte[] serverRandom, byte[] parameters) =>
        [.. clientRandom, .. serverRandom, .. parameters];

    /// <summary>The framed handshake message.</summary>
    public byte[] Serialize()
    {
        var writer = new TlsWriter();
        writer.WriteBytes(EncodeParameters(Group, PublicKey));
        Signed.Write(writer);
        return HandshakeMessage.Frame(HandshakeType.ServerKeyExchange, writer.WrittenSpan);
    }

    /// <summary>Parses a ServerKeyExchange body; only named curves are accepted (RFC 8422 5.4).</summary>
    public static ServerKeyExchange Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        if (reader.ReadUInt8() != NamedCurveType)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.UnsupportedCurveType);
        var group = (TlsNamedGroup)reader.ReadUInt16();
        var point = reader.ReadVector8().ToArray();
        var signed = DigitallySigned.Read(ref reader);
        reader.EnsureEnd();
        return new ServerKeyExchange { Group = group, PublicKey = point, Signed = signed };
    }
}
