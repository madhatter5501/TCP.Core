using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// The shape shared by supported_groups (RFC 8446 4.2.7) and signature_algorithms (RFC 8446 4.2.3): a non-empty
/// vector of 16-bit code points, most preferred first.
/// </summary>
/// <remarks>
/// <code>
/// struct { NamedGroup named_group_list&lt;2..2^16-1&gt;; } NamedGroupList;
/// struct { SignatureScheme supported_signature_algorithms&lt;2..2^16-2&gt;; } SignatureSchemeList;
/// </code>
/// Values this implementation does not know are kept, so a peer's preferences are read as sent.
/// </remarks>
internal static class CodePointListExtension
{
    /// <summary>Encodes <paramref name="values"/> as an extension of <paramref name="type"/>.</summary>
    public static TlsExtension Create<T>(ExtensionType type, IEnumerable<T> values) where T : struct, Enum
    {
        var writer = new TlsWriter();
        using (writer.OpenVector(2))
            foreach (var value in values) writer.WriteUInt16(Convert.ToUInt16(value));
        return new TlsExtension(type, writer.ToArray());
    }

    /// <summary>Decodes the list; an empty list is a decode_error.</summary>
    public static List<T> Parse<T>(ReadOnlySpan<byte> data) where T : struct, Enum
    {
        var reader = new TlsReader(data);
        var list = new TlsReader(reader.ReadVector16());
        reader.EnsureEnd();
        if (list.IsEmpty || list.Remaining % sizeof(ushort) != 0)
            throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        var values = new List<T>();
        while (!list.IsEmpty) values.Add((T)Enum.ToObject(typeof(T), list.ReadUInt16()));
        return values;
    }
}
