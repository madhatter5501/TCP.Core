using System.Net;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// Server Name Indication (RFC 6066 3): the DNS name the client is connecting to, so one address can host many
/// certificates. It is sent in the clear in the ClientHello.
/// </summary>
/// <remarks>
/// <code>
/// struct { NameType name_type; select (name_type) { case host_name: HostName; } name; } ServerName;
/// enum { host_name(0), (255) } NameType;
/// opaque HostName&lt;1..2^16-1&gt;;
/// struct { ServerName server_name_list&lt;1..2^16-1&gt; } ServerNameList;
/// </code>
/// A server that used the name answers with an empty server_name extension. Literal IP addresses are not allowed.
/// </remarks>
internal static class ServerNameExtension
{
    private const byte HostNameType = 0;

    /// <summary>The client's extension for <paramref name="host"/>, or null when the host is an IP literal.</summary>
    public static TlsExtension? ForClient(string? host)
    {
        if (string.IsNullOrEmpty(host) || IPAddress.TryParse(host, out _)) return null;
        var writer = new TlsWriter();
        using (writer.OpenVector(2))
        {
            writer.WriteUInt8(HostNameType);
            writer.WriteVector16(System.Text.Encoding.ASCII.GetBytes(host.TrimEnd('.')));
        }
        return new TlsExtension(ExtensionType.ServerName, writer.ToArray());
    }

    /// <summary>The server's acknowledgment: an empty body.</summary>
    public static TlsExtension Acknowledgment { get; } = new(ExtensionType.ServerName, []);

    /// <summary>The host name in a client's extension.</summary>
    public static string Parse(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var list = new TlsReader(reader.ReadVector16());
        reader.EnsureEnd();
        string? host = null;
        while (!list.IsEmpty)
        {
            var type = list.ReadUInt8();
            var name = list.ReadVector16();
            if (type == HostNameType && host is null) host = System.Text.Encoding.ASCII.GetString(name);
        }
        if (string.IsNullOrEmpty(host)) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidServerName);
        return host;
    }
}
