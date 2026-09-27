using System.Security.Cryptography;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Authenticated encryption with associated data: one call both encrypts and computes a tag over the ciphertext
/// and some unencrypted header bytes, and decryption fails as a whole if either was altered.
/// </summary>
/// <remarks>
/// .NET's <see cref="AesGcm"/> and <see cref="ChaCha20Poly1305"/> have the same shape but no common interface;
/// this hides which one a suite chose. The algorithms are the platform's; TLS only decides the key, nonce and
/// associated data.
/// </remarks>
internal sealed class AeadCipher : IDisposable
{
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha;

    /// <summary>Creates a cipher for <paramref name="algorithm"/> keyed with <paramref name="key"/>.</summary>
    public AeadCipher(AeadAlgorithm algorithm, byte[] key)
    {
        if (algorithm == AeadAlgorithm.AesGcm) _aesGcm = new AesGcm(key, CipherSuiteInfo.TagLength);
        else _chaCha = new ChaCha20Poly1305(key);
    }

    /// <summary>Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> (same length) and writes the tag.</summary>
    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        if (_aesGcm is not null) _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        else _chaCha!.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <summary>Decrypts and authenticates; false if the tag does not match (the record was forged or corrupted).</summary>
    public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag,
        Span<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        try
        {
            if (_aesGcm is not null) _aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            else _chaCha!.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    /// <summary>Releases the key schedule held by the platform cipher.</summary>
    public void Dispose()
    {
        _aesGcm?.Dispose();
        _chaCha?.Dispose();
    }
}
