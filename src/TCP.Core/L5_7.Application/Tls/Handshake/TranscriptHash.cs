using System.Security.Cryptography;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// The running record of handshake messages whose hash binds keys and signatures to exactly what both sides saw
/// (RFC 8446 4.4.1, RFC 5246 7.4.9).
/// </summary>
/// <remarks>
/// <para>
/// Every handshake message is appended, header included, in the order sent and received. Keys are derived from
/// its hash at fixed points (after ServerHello, after the server's Finished), the server signs it in
/// CertificateVerify, and both Finished messages MAC it, so an attacker who altered any message would make the
/// two sides disagree and the handshake fail.
/// </para>
/// <para>
/// The hash function is the cipher suite's, which is not known until ServerHello, so the messages are kept and
/// hashed on demand rather than fed to a running hash.
/// </para>
/// </remarks>
internal sealed class TranscriptHash
{
    private readonly MemoryStream _messages = new();

    /// <summary>Appends one whole handshake message.</summary>
    public void Add(ReadOnlySpan<byte> message) => _messages.Write(message);

    /// <summary>Transcript-Hash of every message added so far.</summary>
    public byte[] Hash(HashAlgorithmName hash) => CryptographicOperations.HashData(hash, _messages.ToArray());

    /// <summary>
    /// RFC 8446 4.4.1: after a HelloRetryRequest, ClientHello1 is replaced by a synthetic message_hash message
    /// holding its hash, so a stateless server can rebuild the transcript from a cookie:
    /// <c>message_hash (254) || 00 00 || Hash.length || Hash(ClientHello1)</c>.
    /// </summary>
    public void ReplaceWithMessageHash(HashAlgorithmName hash)
    {
        var digest = Hash(hash);
        _messages.SetLength(0);
        Add(HandshakeMessage.Frame(HandshakeType.MessageHash, digest));
    }
}
