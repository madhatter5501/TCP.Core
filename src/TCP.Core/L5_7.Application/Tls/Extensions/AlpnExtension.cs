using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// Application-Layer Protocol Negotiation (RFC 7301): agrees on the protocol that will run inside the TLS
/// connection, such as "h2" (HTTP/2) or "http/1.1", without an extra round trip afterwards.
/// </summary>
/// <remarks>
/// <code>
/// opaque ProtocolName&lt;1..2^8-1&gt;;
/// struct { ProtocolName protocol_name_list&lt;2..2^16-1&gt; } ProtocolNameList;
/// </code>
/// The client lists what it speaks; the server replies with a list of exactly one, chosen by the server's own
/// preference. HTTP/2 over TLS requires this: RFC 9113 3.2 says h2 is only spoken after ALPN selected it. In TLS 1.3
/// the reply is in EncryptedExtensions, so observers cannot see it.
/// </remarks>
internal static class AlpnExtension
{
    /// <summary>Encodes <paramref name="protocols"/>.</summary>
    public static TlsExtension Create(IEnumerable<string> protocols)
    {
        var writer = new TlsWriter();
        using (writer.OpenVector(2))
            foreach (var protocol in protocols) writer.WriteVector8(System.Text.Encoding.ASCII.GetBytes(protocol));
        return new TlsExtension(ExtensionType.ApplicationLayerProtocolNegotiation, writer.ToArray());
    }

    /// <summary>Decodes the list; empty names or an empty list are decode_errors.</summary>
    public static List<string> Parse(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var list = new TlsReader(reader.ReadVector16());
        reader.EnsureEnd();
        var protocols = new List<string>();
        while (!list.IsEmpty)
        {
            var name = list.ReadVector8();
            if (name.IsEmpty) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
            protocols.Add(System.Text.Encoding.ASCII.GetString(name));
        }
        if (protocols.Count == 0) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        return protocols;
    }
}
