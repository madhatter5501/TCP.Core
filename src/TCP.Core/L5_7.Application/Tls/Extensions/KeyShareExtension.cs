using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>One (EC)DHE public key and the group it belongs to.</summary>
/// <param name="Group">The group.</param>
/// <param name="KeyExchange">The public key, e.g. an uncompressed P-256 point.</param>
internal readonly record struct KeyShareEntry(TlsNamedGroup Group, byte[] KeyExchange);

/// <summary>
/// key_share (RFC 8446 4.2.8): TLS 1.3 sends Diffie-Hellman public keys inside the hellos, which is what makes a
/// one-round-trip handshake possible.
/// </summary>
/// <remarks>
/// <code>
/// struct { NamedGroup group; opaque key_exchange&lt;1..2^16-1&gt;; } KeyShareEntry;
/// ClientHello:        struct { KeyShareEntry client_shares&lt;0..2^16-1&gt;; } KeyShareClientHello;
/// HelloRetryRequest:  struct { NamedGroup selected_group; } KeyShareHelloRetryRequest;
/// ServerHello:        struct { KeyShareEntry server_share; } KeyShareServerHello;
/// </code>
/// The client guesses which group the server will accept and sends keys for its guesses. If the guess was wrong
/// but the group is in supported_groups, the server replies with a HelloRetryRequest naming the group it wants,
/// costing one extra round trip.
/// </remarks>
internal static class KeyShareExtension
{
    /// <summary>The client's offered shares.</summary>
    public static TlsExtension ForClient(IEnumerable<KeyShareEntry> shares)
    {
        var writer = new TlsWriter();
        using (writer.OpenVector(2))
            foreach (var share in shares) WriteEntry(writer, share);
        return new TlsExtension(ExtensionType.KeyShare, writer.ToArray());
    }

    /// <summary>The server's single share.</summary>
    public static TlsExtension ForServer(KeyShareEntry share)
    {
        var writer = new TlsWriter();
        WriteEntry(writer, share);
        return new TlsExtension(ExtensionType.KeyShare, writer.ToArray());
    }

    /// <summary>A HelloRetryRequest's request for a share in <paramref name="group"/>.</summary>
    public static TlsExtension ForRetry(TlsNamedGroup group)
    {
        var writer = new TlsWriter();
        writer.WriteUInt16((ushort)group);
        return new TlsExtension(ExtensionType.KeyShare, writer.ToArray());
    }

    /// <summary>Parses a client's shares; a group repeated is an illegal_parameter (RFC 8446 4.2.8).</summary>
    public static List<KeyShareEntry> ParseClient(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var list = new TlsReader(reader.ReadVector16());
        reader.EnsureEnd();
        var shares = new List<KeyShareEntry>();
        while (!list.IsEmpty)
        {
            var share = ReadEntry(ref list);
            if (shares.Any(s => s.Group == share.Group))
                throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.DuplicateKeyShare);
            shares.Add(share);
        }
        return shares;
    }

    /// <summary>Parses a ServerHello's share.</summary>
    public static KeyShareEntry ParseServer(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var share = ReadEntry(ref reader);
        reader.EnsureEnd();
        return share;
    }

    /// <summary>Parses a HelloRetryRequest's selected group.</summary>
    public static TlsNamedGroup ParseRetry(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var group = (TlsNamedGroup)reader.ReadUInt16();
        reader.EnsureEnd();
        return group;
    }

    private static void WriteEntry(TlsWriter writer, KeyShareEntry share)
    {
        writer.WriteUInt16((ushort)share.Group);
        writer.WriteVector16(share.KeyExchange);
    }

    private static KeyShareEntry ReadEntry(ref TlsReader reader)
    {
        var group = (TlsNamedGroup)reader.ReadUInt16();
        var key = reader.ReadVector16();
        if (key.IsEmpty) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidKeyShare);
        return new KeyShareEntry(group, [.. key]);
    }
}
