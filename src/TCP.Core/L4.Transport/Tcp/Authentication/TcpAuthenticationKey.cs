using System.Net;

namespace TCP.L4.Transport.Tcp.Authentication;

/// <summary>How segments to and from a peer are authenticated.</summary>
public enum TcpAuthenticationAlgorithm
{
    /// <summary>TCP-AO (RFC 5925) with HMAC-SHA-1-96 and its HMAC-SHA-1 key derivation (RFC 5926).</summary>
    HmacSha1,
    /// <summary>TCP-AO (RFC 5925) with AES-128-CMAC-96 and its AES-CMAC key derivation (RFC 5926).</summary>
    AesCmac128,
    /// <summary>The older TCP MD5 Signature option (RFC 2385), still common for BGP sessions. Obsoleted by TCP-AO.</summary>
    Md5
}

/// <summary>
/// A pre-shared key that protects every segment of connections with <see cref="Peer"/>: the Master Key Tuple of
/// TCP-AO (RFC 5925 3.1), or an RFC 2385 MD5 key. Register it with <see cref="TcpHost.AddAuthenticationKey"/>.
/// </summary>
/// <remarks>
/// Once a key covers a peer, segments to it are signed and segments from it without a valid signature are
/// discarded silently, including RSTs, which is the point: an off-path attacker can no longer reset or inject into
/// the connection. Several TCP-AO keys with different identifiers may cover one peer, which allows rolling to a new
/// key without dropping connections.
/// </remarks>
/// <param name="Peer">The remote address this key applies to.</param>
/// <param name="MasterKey">The shared secret. It must match the peer's configuration exactly.</param>
/// <param name="Algorithm">The MAC algorithm, which both ends must agree on out of band.</param>
/// <param name="SendId">TCP-AO KeyID we put in segments we sign with this key. Ignored for MD5.</param>
/// <param name="ReceiveId">TCP-AO KeyID the peer uses when it signs with this key. Ignored for MD5.</param>
public sealed record TcpAuthenticationKey(IPAddress Peer, byte[] MasterKey,
    TcpAuthenticationAlgorithm Algorithm = TcpAuthenticationAlgorithm.HmacSha1, byte SendId = 0, byte ReceiveId = 0)
{
    /// <summary>Local port the key is limited to, or null for any.</summary>
    public ushort? LocalPort { get; init; }

    /// <summary>Remote port the key is limited to, or null for any.</summary>
    public ushort? RemotePort { get; init; }

    /// <summary>TCP-AO only: whether options other than TCP-AO itself are covered by the MAC (RFC 5925 3.1). Default true.</summary>
    public bool IncludeOptions { get; init; } = true;

    /// <summary>Whether this key covers a connection between these ports and addresses.</summary>
    internal bool Matches(IPAddress peer, ushort localPort, ushort remotePort) =>
        Peer.Equals(peer) && (LocalPort is null || LocalPort == localPort) && (RemotePort is null || RemotePort == remotePort);
}
