using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// One extension exactly as sent: its type and its still-encoded body.
/// </summary>
/// <remarks>
/// <code>
/// struct { ExtensionType extension_type; opaque extension_data&lt;0..2^16-1&gt;; } Extension;   // RFC 8446 4.2
/// </code>
/// Bodies stay encoded until a handshake step needs them, so a parsed message re-serializes to identical bytes;
/// that is what lets the tests compare our messages with RFC 8448 byte for byte.
/// </remarks>
internal readonly record struct TlsExtension(ExtensionType Type, byte[] Data)
{
    /// <summary>Reads an <c>Extension extensions&lt;..2^16-1&gt;</c> vector's contents.</summary>
    /// <exception cref="TlsAlertException">Malformed (decode_error) or a type appears twice (illegal_parameter, RFC 8446 4.2).</exception>
    public static List<TlsExtension> ParseList(ReadOnlySpan<byte> contents)
    {
        var reader = new TlsReader(contents);
        var extensions = new List<TlsExtension>();
        while (!reader.IsEmpty)
        {
            var type = (ExtensionType)reader.ReadUInt16();
            if (extensions.Any(e => e.Type == type))
                throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.DuplicateExtension);
            extensions.Add(new TlsExtension(type, [.. reader.ReadVector16()]));
        }
        return extensions;
    }

    /// <summary>Writes <paramref name="extensions"/> as a vector with a 2-byte length.</summary>
    public static void WriteList(TlsWriter writer, IEnumerable<TlsExtension> extensions)
    {
        using var _ = writer.OpenVector(2);
        foreach (var extension in extensions)
        {
            writer.WriteUInt16((ushort)extension.Type);
            writer.WriteVector16(extension.Data);
        }
    }
}

/// <summary>Lookup helpers over a parsed extension list.</summary>
internal static class TlsExtensionListExtensions
{
    /// <summary>The body of the extension of <paramref name="type"/>, or null if absent.</summary>
    public static byte[]? Find(this IReadOnlyList<TlsExtension> extensions, ExtensionType type)
    {
        foreach (var extension in extensions)
            if (extension.Type == type) return extension.Data;
        return null;
    }

    /// <summary>The extension of <paramref name="type"/> is present.</summary>
    public static bool Has(this IReadOnlyList<TlsExtension> extensions, ExtensionType type) => extensions.Find(type) is not null;
}
