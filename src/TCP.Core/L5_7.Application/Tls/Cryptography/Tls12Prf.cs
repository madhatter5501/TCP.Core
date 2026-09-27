using System.Security.Cryptography;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// The TLS 1.2 pseudorandom function (RFC 5246 5) and the secrets it derives: the master secret (classic or
/// extended, RFC 7627), the key block, and Finished verify_data.
/// </summary>
/// <remarks>
/// <para>
/// P_hash expands a secret into any amount of output by chaining HMAC:
/// <code>
/// A(0) = seed;  A(i) = HMAC(secret, A(i-1))
/// P_hash(secret, seed) = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
/// PRF(secret, label, seed) = P_&lt;hash&gt;(secret, label + seed)
/// </code>
/// The hash is SHA-256 unless the suite names another (SHA-384 for the AES-256 suites). TLS 1.3 replaced this with
/// HKDF, which has the same extract-then-expand idea with a cleaner security proof.
/// </para>
/// <para>
/// The classic master secret mixes only the two hello randoms with the premaster secret, so a man in the middle
/// who runs separate handshakes with each side can make both sessions share one master secret (the "triple
/// handshake" attack). RFC 7627's extended master secret instead hashes the whole handshake up to
/// ClientKeyExchange, binding the secret to the certificates and key exchange actually seen.
/// </para>
/// </remarks>
internal static class Tls12Prf
{
    /// <summary>The master secret is always 48 bytes (RFC 5246 8.1).</summary>
    public const int MasterSecretLength = 48;
    /// <summary>verify_data is 12 bytes for every cipher suite defined so far (RFC 5246 7.4.9).</summary>
    public const int VerifyDataLength = 12;
    private const string MasterSecretLabel = "master secret";
    private const string ExtendedMasterSecretLabel = "extended master secret";
    private const string KeyExpansionLabel = "key expansion";
    private const string ClientFinishedLabel = "client finished";
    private const string ServerFinishedLabel = "server finished";

    /// <summary>PRF(secret, label, seed) truncated to <paramref name="length"/> bytes.</summary>
    public static byte[] Compute(HashAlgorithmName hash, byte[] secret, string label, ReadOnlySpan<byte> seed, int length)
    {
        byte[] labelSeed = [.. System.Text.Encoding.ASCII.GetBytes(label), .. seed];
        var output = new byte[length];
        var a = labelSeed; // A(0)
        for (var offset = 0; offset < length;)
        {
            a = CryptographicOperations.HmacData(hash, secret, a); // A(i)
            byte[] input = [.. a, .. labelSeed];
            var block = CryptographicOperations.HmacData(hash, secret, input);
            var count = Math.Min(block.Length, length - offset);
            block.AsSpan(0, count).CopyTo(output.AsSpan(offset));
            offset += count;
        }
        return output;
    }

    /// <summary>RFC 5246 8.1: PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47].</summary>
    public static byte[] MasterSecret(HashAlgorithmName hash, byte[] premasterSecret, ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> serverRandom) =>
        Compute(hash, premasterSecret, MasterSecretLabel, [.. clientRandom, .. serverRandom], MasterSecretLength);

    /// <summary>RFC 7627 4: PRF(pre_master_secret, "extended master secret", session_hash)[0..47].</summary>
    /// <param name="sessionHash">Hash of every handshake message up to and including ClientKeyExchange.</param>
    public static byte[] ExtendedMasterSecret(HashAlgorithmName hash, byte[] premasterSecret, byte[] sessionHash) =>
        Compute(hash, premasterSecret, ExtendedMasterSecretLabel, sessionHash, MasterSecretLength);

    /// <summary>
    /// RFC 5246 6.3: key_block = PRF(master_secret, "key expansion", server_random + client_random), sliced into
    /// client_write_key, server_write_key, client_write_IV and server_write_IV. AEAD suites need no MAC keys.
    /// Note the randoms are in the opposite order from the master secret derivation.
    /// </summary>
    public static (byte[] ClientKey, byte[] ServerKey, byte[] ClientIv, byte[] ServerIv) KeyBlock(
        CipherSuiteInfo suite, byte[] masterSecret, ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> serverRandom)
    {
        var block = Compute(suite.Hash, masterSecret, KeyExpansionLabel, [.. serverRandom, .. clientRandom],
            2 * (suite.KeyLength + suite.IvLength));
        var offset = 0;
        byte[] Next(int length) { var part = block.AsSpan(offset, length).ToArray(); offset += length; return part; }
        return (Next(suite.KeyLength), Next(suite.KeyLength), Next(suite.IvLength), Next(suite.IvLength));
    }

    /// <summary>
    /// RFC 5246 7.4.9: verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11], where
    /// the messages are every handshake message so far, not counting this Finished.
    /// </summary>
    public static byte[] VerifyData(HashAlgorithmName hash, byte[] masterSecret, bool fromServer, byte[] handshakeHash) =>
        Compute(hash, masterSecret, fromServer ? ServerFinishedLabel : ClientFinishedLabel, handshakeHash, VerifyDataLength);
}
