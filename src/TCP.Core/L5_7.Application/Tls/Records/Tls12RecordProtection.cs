using System.Buffers.Binary;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// TLS 1.2 AES-GCM record protection (RFC 5246 6.2.3.3, RFC 5288 3).
/// </summary>
/// <remarks>
/// <para>
/// The 12-byte GCM nonce is split: a 4-byte "salt" derived from the key block and never sent, and an 8-byte
/// explicit part carried at the front of every record. RFC 5288 only requires the explicit part to be unique;
/// like most implementations this sends the sequence number.
/// </para>
/// <para>
/// Unlike TLS 1.3 the content type stays visible in the header, and the additional data is built from the
/// sequence number and the plaintext's type, version and length:
/// <code>
/// additional_data = seq_num (8) + TLSCompressed.type (1) + TLSCompressed.version (2) + TLSCompressed.length (2)
/// fragment        = nonce_explicit (8) + ciphertext + tag (16)
/// </code>
/// </para>
/// </remarks>
internal sealed class Tls12RecordProtection(CipherSuiteInfo suite, byte[] key, byte[] salt) : RecordProtection(suite, key, salt)
{
    private const int ExplicitNonceLength = 8;
    private const int AdditionalDataLength = 13; // seq_num (8) + type (1) + version (2) + length (2)
    private const ushort RecordVersion = (ushort)TlsVersion.Tls12;

    /// <inheritdoc/>
    public override byte[] Protect(ContentType type, ReadOnlySpan<byte> plaintext, ulong sequence)
    {
        var fragmentLength = ExplicitNonceLength + plaintext.Length + CipherSuiteInfo.TagLength;
        var record = new byte[TlsRecord.HeaderLength + fragmentLength];
        TlsRecord.CreateHeader(type, RecordVersion, fragmentLength).CopyTo(record, 0);
        var fragment = record.AsSpan(TlsRecord.HeaderLength);
        WriteSequence(fragment, sequence); // The explicit nonce is the sequence number.
        Cipher.Encrypt(Nonce(fragment[..ExplicitNonceLength]), plaintext,
            fragment.Slice(ExplicitNonceLength, plaintext.Length), fragment[(ExplicitNonceLength + plaintext.Length)..],
            AdditionalData(sequence, type, RecordVersion, plaintext.Length));
        return record;
    }

    /// <inheritdoc/>
    public override (ContentType Type, byte[] Plaintext) Unprotect(TlsRecord record, ulong sequence)
    {
        var plaintextLength = record.Fragment.Length - ExplicitNonceLength - CipherSuiteInfo.TagLength;
        if (plaintextLength < 0)
            throw new TlsAlertException(TlsAlertDescription.BadRecordMac, TlsMessages.RecordAuthenticationFailed);
        if (plaintextLength > TlsRecord.MaximumPlaintextLength)
            throw new TlsAlertException(TlsAlertDescription.RecordOverflow, TlsMessages.RecordTooLong);
        var fragment = record.Fragment.AsSpan();
        var plaintext = new byte[plaintextLength];
        if (!Cipher.TryDecrypt(Nonce(fragment[..ExplicitNonceLength]), fragment.Slice(ExplicitNonceLength, plaintextLength),
                fragment[(ExplicitNonceLength + plaintextLength)..], plaintext,
                AdditionalData(sequence, record.Type, record.Version, plaintextLength)))
            throw new TlsAlertException(TlsAlertDescription.BadRecordMac, TlsMessages.RecordAuthenticationFailed);
        return (record.Type, plaintext);
    }

    /// <summary>GCMNonce = salt (4, from the key block) + nonce_explicit (8, from the record).</summary>
    private byte[] Nonce(ReadOnlySpan<byte> explicitNonce)
    {
        var nonce = new byte[CipherSuiteInfo.NonceLength];
        Iv.CopyTo(nonce, 0);
        explicitNonce.CopyTo(nonce.AsSpan(Iv.Length));
        return nonce;
    }

    /// <summary>RFC 5246 6.2.3.3: seq_num + type + version + length of the plaintext.</summary>
    private static byte[] AdditionalData(ulong sequence, ContentType type, ushort version, int length)
    {
        var data = new byte[AdditionalDataLength];
        WriteSequence(data, sequence);
        data[SequenceLength] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(SequenceLength + 1), version);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(SequenceLength + 3), (ushort)length);
        return data;
    }
}
