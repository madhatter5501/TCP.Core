using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// TLS 1.3 record protection (RFC 8446 5.2-5.3).
/// </summary>
/// <remarks>
/// <para>
/// The plaintext is extended into a <c>TLSInnerPlaintext</c>: the content, then the real content type byte, then
/// optional zero padding that hides the true length. That whole thing is encrypted and sent as a record whose outer
/// type is always application_data and whose version is always 0x0303:
/// <code>
/// struct {
///     opaque content[TLSPlaintext.length];
///     ContentType type;
///     uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
/// </code>
/// </para>
/// <para>
/// The nonce is the 12-byte write IV XORed with the 64-bit record sequence number, left-padded with zeros. The
/// additional data is the 5-byte record header, so tampering with the announced length is detected too.
/// </para>
/// </remarks>
internal sealed class Tls13RecordProtection(CipherSuiteInfo suite, byte[] key, byte[] iv) : RecordProtection(suite, key, iv)
{
    private const ushort LegacyRecordVersion = (ushort)TlsVersion.Tls12;

    /// <inheritdoc/>
    public override byte[] Protect(ContentType type, ReadOnlySpan<byte> plaintext, ulong sequence)
    {
        var innerLength = plaintext.Length + sizeof(ContentType);
        var header = TlsRecord.CreateHeader(ContentType.ApplicationData, LegacyRecordVersion, innerLength + CipherSuiteInfo.TagLength);
        var inner = new byte[innerLength];
        plaintext.CopyTo(inner);
        inner[^1] = (byte)type; // No padding: this implementation does not hide record lengths.
        var record = new byte[TlsRecord.HeaderLength + innerLength + CipherSuiteInfo.TagLength];
        header.CopyTo(record, 0);
        var fragment = record.AsSpan(TlsRecord.HeaderLength);
        Cipher.Encrypt(Nonce(sequence), inner, fragment[..innerLength], fragment[innerLength..], header);
        return record;
    }

    /// <inheritdoc/>
    public override (ContentType Type, byte[] Plaintext) Unprotect(TlsRecord record, ulong sequence)
    {
        if (record.Type != ContentType.ApplicationData)
            throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.PlaintextAfterKeys);
        if (record.Fragment.Length > TlsRecord.MaximumTls13CiphertextLength)
            throw new TlsAlertException(TlsAlertDescription.RecordOverflow, TlsMessages.RecordTooLong);
        var innerLength = record.Fragment.Length - CipherSuiteInfo.TagLength;
        if (innerLength < sizeof(ContentType))
            throw new TlsAlertException(TlsAlertDescription.BadRecordMac, TlsMessages.RecordAuthenticationFailed);
        var inner = new byte[innerLength];
        if (!Cipher.TryDecrypt(Nonce(sequence), record.Fragment.AsSpan(0, innerLength), record.Fragment.AsSpan(innerLength),
                inner, record.Header))
            throw new TlsAlertException(TlsAlertDescription.BadRecordMac, TlsMessages.RecordAuthenticationFailed);
        // Scan back over the padding: the last non-zero byte is the real content type (RFC 8446 5.4).
        var typeIndex = Array.FindLastIndex(inner, b => b != 0);
        if (typeIndex < 0) throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.AllPadding);
        if (typeIndex > TlsRecord.MaximumPlaintextLength)
            throw new TlsAlertException(TlsAlertDescription.RecordOverflow, TlsMessages.RecordTooLong);
        return ((ContentType)inner[typeIndex], inner[..typeIndex]);
    }

    /// <summary>RFC 8446 5.3: the sequence number, big-endian and left-padded to 12 bytes, XORed with the write IV.</summary>
    private byte[] Nonce(ulong sequence)
    {
        var nonce = (byte[])Iv.Clone();
        Span<byte> encoded = stackalloc byte[SequenceLength];
        WriteSequence(encoded, sequence);
        var offset = nonce.Length - SequenceLength;
        for (var i = 0; i < SequenceLength; i++) nonce[offset + i] ^= encoded[i];
        return nonce;
    }
}
