using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// A certificate chain: the sender's own (leaf) certificate first, then any intermediates toward a trusted root.
/// </summary>
/// <remarks>
/// <code>
/// TLS 1.2 (RFC 5246 7.4.2):  opaque ASN.1Cert&lt;1..2^24-1&gt;;  struct { ASN.1Cert certificate_list&lt;0..2^24-1&gt;; } Certificate;
/// TLS 1.3 (RFC 8446 4.4.2):  struct { opaque cert_data&lt;1..2^24-1&gt;; Extension extensions&lt;0..2^16-1&gt;; } CertificateEntry;
///                            struct { opaque certificate_request_context&lt;0..2^8-1&gt;; CertificateEntry certificate_list&lt;0..2^24-1&gt;; } Certificate;
/// </code>
/// Certificates are DER-encoded X.509. TLS 1.3 gives each entry its own extensions (for OCSP staples and signed
/// certificate timestamps), which this implementation neither sends nor needs.
/// </remarks>
internal sealed class CertificateMessage
{
    /// <summary>TLS 1.3: empty in a handshake, or echoes a CertificateRequest's context.</summary>
    public byte[] RequestContext { get; init; } = [];

    /// <summary>DER certificates, leaf first.</summary>
    public required List<byte[]> Certificates { get; init; }

    /// <summary>The framed handshake message for <paramref name="version"/>.</summary>
    public byte[] Serialize(TlsVersion version)
    {
        var writer = new TlsWriter();
        if (version == TlsVersion.Tls13) writer.WriteVector8(RequestContext);
        using (writer.OpenVector(TlsWriter.UInt24Length))
        {
            foreach (var certificate in Certificates)
            {
                writer.WriteVector24(certificate);
                if (version == TlsVersion.Tls13) writer.WriteVector16([]); // No per-certificate extensions.
            }
        }
        return HandshakeMessage.Frame(HandshakeType.Certificate, writer.WrittenSpan);
    }

    /// <summary>Parses a Certificate body in <paramref name="version"/>'s format.</summary>
    public static CertificateMessage Parse(ReadOnlySpan<byte> body, TlsVersion version)
    {
        var reader = new TlsReader(body);
        var context = version == TlsVersion.Tls13 ? reader.ReadVector8().ToArray() : [];
        var list = new TlsReader(reader.ReadVector24());
        reader.EnsureEnd();
        var certificates = new List<byte[]>();
        while (!list.IsEmpty)
        {
            certificates.Add([.. list.ReadVector24()]);
            if (version == TlsVersion.Tls13) list.ReadVector16(); // Entry extensions are ignored.
        }
        return new CertificateMessage { RequestContext = context, Certificates = certificates };
    }
}
