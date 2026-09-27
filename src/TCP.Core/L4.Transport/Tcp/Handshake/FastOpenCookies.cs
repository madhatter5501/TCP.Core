using System.Net;
using System.Security.Cryptography;

namespace TCP.L4.Transport.Tcp.Handshake;

/// <summary>Server side of TCP Fast Open (RFC 7413 4.1.2): issues and checks cookies bound to a client address.</summary>
/// <remarks>
/// Fast Open lets a client put its request in the SYN, saving a round trip on every repeat connection. Accepting
/// data before the handshake invites spoofed floods, so the server first hands the client a cookie (a MAC of its
/// IP address under a server secret) on an ordinary handshake. Later SYNs that present that cookie prove the client
/// can receive at its address, and their data is accepted at once.
/// </remarks>
internal sealed class FastOpenCookieGenerator
{
    private const int SecretBytes = 32;
    private const int CookieLength = 8;

    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(SecretBytes);

    /// <summary>The cookie for <paramref name="client"/>: the first 8 bytes of HMAC-SHA256(secret, address).</summary>
    public byte[] Create(IPAddress client) => HMACSHA256.HashData(_secret, client.GetAddressBytes())[..CookieLength];

    /// <summary>Whether <paramref name="cookie"/> is the one this server issued to <paramref name="client"/>.</summary>
    public bool IsValid(IPAddress client, ReadOnlySpan<byte> cookie) =>
        cookie.Length == CookieLength && CryptographicOperations.FixedTimeEquals(cookie, Create(client));
}

/// <summary>Client side of TCP Fast Open: cookies (and MSS) learned from each server, for later SYNs with data.</summary>
internal sealed class FastOpenCookieCache
{
    private const int MaximumEntries = 256;

    private readonly Dictionary<IPAddress, (byte[] Cookie, ushort Mss)> _entries = [];

    /// <summary>The cookie and MSS last learned from <paramref name="server"/>, if any.</summary>
    public bool TryGet(IPAddress server, out byte[] cookie, out ushort mss)
    {
        var found = _entries.TryGetValue(server, out var entry);
        (cookie, mss) = found ? entry : ([], default);
        return found;
    }

    /// <summary>Remembers a cookie the server sent on a SYN-ACK. The cache is bounded; when full, an arbitrary entry is evicted.</summary>
    public void Store(IPAddress server, byte[] cookie, ushort mss)
    {
        if (_entries.Count >= MaximumEntries && !_entries.ContainsKey(server)) _entries.Remove(_entries.Keys.First());
        _entries[server] = (cookie, mss);
    }

    /// <summary>Forgets a server's cookie, after it ignored our SYN data (RFC 7413 4.1.3 suggests falling back).</summary>
    public void Remove(IPAddress server) => _entries.Remove(server);
}
