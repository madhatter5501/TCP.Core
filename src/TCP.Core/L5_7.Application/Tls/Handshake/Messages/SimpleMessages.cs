using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// Handshake messages with one-field bodies: EncryptedExtensions, Finished, ServerHelloDone, ClientKeyExchange,
/// KeyUpdate and CertificateRequest.
/// </summary>
internal static class SimpleMessages
{
    /// <summary>KeyUpdate's request_update values (RFC 8446 4.6.3).</summary>
    public const byte UpdateNotRequested = 0;
    /// <summary>The sender also wants the receiver to update its sending keys.</summary>
    public const byte UpdateRequested = 1;

    /// <summary>
    /// TLS 1.3 EncryptedExtensions (RFC 8446 4.3.1): <c>struct { Extension extensions&lt;0..2^16-1&gt;; }</c>. Server
    /// extensions that do not affect key establishment (ALPN, server_name, record_size_limit) move here so they
    /// are encrypted.
    /// </summary>
    public static byte[] EncryptedExtensions(IEnumerable<TlsExtension> extensions)
    {
        var writer = new TlsWriter();
        TlsExtension.WriteList(writer, extensions);
        return HandshakeMessage.Frame(HandshakeType.EncryptedExtensions, writer.WrittenSpan);
    }

    /// <summary>Parses EncryptedExtensions.</summary>
    public static List<TlsExtension> ParseEncryptedExtensions(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var extensions = TlsExtension.ParseList(reader.ReadVector16());
        reader.EnsureEnd();
        return extensions;
    }

    /// <summary>Finished (RFC 8446 4.4.4, RFC 5246 7.4.9): <c>opaque verify_data[Hash.length or 12]</c>, no length prefix.</summary>
    public static byte[] Finished(byte[] verifyData) => HandshakeMessage.Frame(HandshakeType.Finished, verifyData);

    /// <summary>TLS 1.2 ServerHelloDone (RFC 5246 7.4.5): an empty body ending the server's first flight.</summary>
    public static byte[] ServerHelloDone() => HandshakeMessage.Frame(HandshakeType.ServerHelloDone, []);

    /// <summary>TLS 1.2 ECDHE ClientKeyExchange (RFC 8422 5.7): <c>opaque point&lt;1..2^8-1&gt;</c>, the client's public key.</summary>
    public static byte[] ClientKeyExchange(byte[] publicKey)
    {
        var writer = new TlsWriter();
        writer.WriteVector8(publicKey);
        return HandshakeMessage.Frame(HandshakeType.ClientKeyExchange, writer.WrittenSpan);
    }

    /// <summary>Parses ClientKeyExchange.</summary>
    public static byte[] ParseClientKeyExchange(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var point = reader.ReadVector8().ToArray();
        reader.EnsureEnd();
        if (point.Length == 0) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidKeyShare);
        return point;
    }

    /// <summary>TLS 1.3 KeyUpdate (RFC 8446 4.6.3): <c>enum { update_not_requested(0), update_requested(1) } request_update</c>.</summary>
    public static byte[] KeyUpdate(bool requestUpdate) =>
        HandshakeMessage.Frame(HandshakeType.KeyUpdate, [requestUpdate ? UpdateRequested : UpdateNotRequested]);

    /// <summary>Parses KeyUpdate; any value other than 0 or 1 is an illegal_parameter.</summary>
    public static bool ParseKeyUpdate(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var value = reader.ReadUInt8();
        reader.EnsureEnd();
        return value switch
        {
            UpdateNotRequested => false,
            UpdateRequested => true,
            _ => throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.InvalidKeyUpdate),
        };
    }

    /// <summary>
    /// The certificate_request_context of a TLS 1.3 CertificateRequest (RFC 8446 4.3.2), which a client without a
    /// certificate must echo in an empty Certificate message. The rest (acceptable signature algorithms and CAs)
    /// matters only to a client that has one.
    /// </summary>
    public static byte[] ParseCertificateRequestContext(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var context = reader.ReadVector8().ToArray();
        TlsExtension.ParseList(reader.ReadVector16());
        reader.EnsureEnd();
        return context;
    }
}
