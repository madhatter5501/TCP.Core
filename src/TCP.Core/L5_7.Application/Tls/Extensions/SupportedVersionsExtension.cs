using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// supported_versions (RFC 8446 4.2.1): where TLS 1.3 is really negotiated. The client lists versions it supports;
/// the server answers with the single version it picked.
/// </summary>
/// <remarks>
/// <code>
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello: ProtocolVersion versions&lt;2..254&gt;;
///         case server_hello: ProtocolVersion selected_version;   // also HelloRetryRequest
///     };
/// } SupportedVersions;
/// </code>
/// A TLS 1.2 server does not know the extension and ignores it, then negotiates from legacy_version as before, so
/// one ClientHello works with both generations.
/// </remarks>
internal static class SupportedVersionsExtension
{
    /// <summary>The client's list, most preferred first.</summary>
    public static TlsExtension ForClient(IEnumerable<TlsVersion> versions)
    {
        var writer = new TlsWriter();
        using (writer.OpenVector(1))
            foreach (var version in versions) writer.WriteUInt16((ushort)version);
        return new TlsExtension(ExtensionType.SupportedVersions, writer.ToArray());
    }

    /// <summary>The server's choice.</summary>
    public static TlsExtension ForServer(TlsVersion version)
    {
        var writer = new TlsWriter();
        writer.WriteUInt16((ushort)version);
        return new TlsExtension(ExtensionType.SupportedVersions, writer.ToArray());
    }

    /// <summary>The versions a client listed, including ones this implementation does not know.</summary>
    public static List<ushort> ParseClient(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var list = new TlsReader(reader.ReadVector8());
        reader.EnsureEnd();
        if (list.IsEmpty || list.Remaining % sizeof(ushort) != 0)
            throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        var versions = new List<ushort>();
        while (!list.IsEmpty) versions.Add(list.ReadUInt16());
        return versions;
    }

    /// <summary>The version a server selected.</summary>
    public static ushort ParseServer(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var version = reader.ReadUInt16();
        reader.EnsureEnd();
        return version;
    }
}
