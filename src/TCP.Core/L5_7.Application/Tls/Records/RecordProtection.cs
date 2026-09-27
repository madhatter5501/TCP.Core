using System.Buffers.Binary;
using TCP.L5_7.Application.Tls.Cryptography;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// The keys of one direction in one epoch, and the rules for sealing records with them. A connection starts with
/// no protection (plaintext hellos); the handshake installs a new instance each time the keys change.
/// </summary>
/// <remarks>
/// Both versions use an AEAD with a unique nonce per record, built from a per-direction secret IV and the record's
/// 64-bit sequence number. The sequence number is never sent in TLS 1.3 (it is implicit in record order); TLS 1.2
/// GCM sends 8 nonce bytes explicitly. Reusing a nonce under one key would break GCM completely, which is why the
/// sequence number restarts only when the key changes.
/// </remarks>
internal abstract class RecordProtection(CipherSuiteInfo suite, byte[] key, byte[] iv) : IDisposable
{
    private const int SequenceNumberLength = sizeof(ulong);

    /// <summary>The negotiated suite.</summary>
    protected CipherSuiteInfo Suite { get; } = suite;

    /// <summary>The AEAD keyed for this direction and epoch.</summary>
    protected AeadCipher Cipher { get; } = suite.CreateAead(key);

    /// <summary>The per-direction IV: a full nonce base in TLS 1.3, a 4-byte salt in TLS 1.2.</summary>
    protected byte[] Iv { get; } = iv;

    /// <summary>The AEAD key, kept for tests that compare it with published traces.</summary>
    public byte[] Key { get; } = key;

    /// <summary>The IV, kept for tests that compare it with published traces.</summary>
    public byte[] InitializationVector => Iv;

    /// <summary>Encrypts <paramref name="plaintext"/> of <paramref name="type"/> as record number <paramref name="sequence"/>.</summary>
    /// <returns>The complete record: header and protected fragment.</returns>
    public abstract byte[] Protect(ContentType type, ReadOnlySpan<byte> plaintext, ulong sequence);

    /// <summary>Authenticates and decrypts record number <paramref name="sequence"/>.</summary>
    /// <returns>The true content type and plaintext.</returns>
    /// <exception cref="Alerts.TlsAlertException">bad_record_mac, record_overflow or unexpected_message.</exception>
    public abstract (ContentType Type, byte[] Plaintext) Unprotect(TlsRecord record, ulong sequence);

    /// <summary>Writes <paramref name="sequence"/> as the 8-byte big-endian <c>seq_num</c>.</summary>
    protected static void WriteSequence(Span<byte> destination, ulong sequence) =>
        BinaryPrimitives.WriteUInt64BigEndian(destination[..SequenceNumberLength], sequence);

    /// <summary>Length of the encoded sequence number.</summary>
    protected static int SequenceLength => SequenceNumberLength;

    /// <summary>Releases the cipher.</summary>
    public void Dispose() => Cipher.Dispose();
}
