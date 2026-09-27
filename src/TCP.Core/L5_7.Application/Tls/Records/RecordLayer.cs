using System.Buffers;
using TCP.L5_7.Application.Tls.Alerts;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// The TLS record protocol (RFC 8446 5, RFC 5246 6): turns sub-protocol messages into protected records and back.
/// </summary>
/// <remarks>
/// <para>
/// Each direction has its own current <see cref="RecordProtection"/> (none until the handshake installs keys) and
/// its own 64-bit sequence number, which counts records under the current keys and restarts at zero whenever they
/// change. Everything the handshake writes goes through here, so key changes and record boundaries line up.
/// </para>
/// <para>
/// Handshake messages written in one flight are coalesced: they accumulate until the flight ends or the write keys
/// change, then go out in as few records as the fragment limit allows. A TLS 1.3 server's EncryptedExtensions,
/// Certificate, CertificateVerify and Finished therefore share a single record, as in RFC 8448's traces.
/// </para>
/// </remarks>
internal sealed class RecordLayer
{
    private static readonly byte[] ChangeCipherSpecBody = [1];

    private readonly RecordReader _reader = new();
    private readonly ArrayBufferWriter<byte> _output = new();
    private readonly ArrayBufferWriter<byte> _pendingHandshake = new();
    private ulong _readSequence;
    private ulong _writeSequence;

    /// <summary>
    /// The legacy_record_version for records we write. RFC 8446 5.1 lets a client's first ClientHello say 0x0301
    /// for the sake of old servers; everything else says 0x0303.
    /// </summary>
    public ushort WriteVersion { get; set; } = (ushort)TlsVersion.Tls12;

    /// <summary>Largest plaintext we put in one record: 2^14, or less if the peer asked (RFC 8449).</summary>
    public int MaximumFragmentLength { get; set; } = TlsRecord.MaximumPlaintextLength;

    /// <summary>
    /// Accept unencrypted alerts after TLS 1.3 keys are in place. A peer that fails to process our ServerHello has
    /// no keys yet and can only complain in plaintext; reading its alert makes the failure diagnosable.
    /// </summary>
    public bool AcceptPlaintextAlerts { get; set; }

    /// <summary>Protection applied to incoming records, or null while they are plaintext.</summary>
    public RecordProtection? ReadProtection { get; private set; }

    /// <summary>Protection applied to outgoing records, or null while they are plaintext.</summary>
    public RecordProtection? WriteProtection { get; private set; }

    /// <summary>Some bytes of an incomplete record are buffered.</summary>
    public bool HasPartialRecord => _reader.HasPartialRecord;

    /// <summary>Records are waiting to be taken by <see cref="TakeOutput"/>.</summary>
    public bool HasOutput => _output.WrittenCount > 0 || _pendingHandshake.WrittenCount > 0;

    /// <summary>Adds received stream bytes.</summary>
    public void Append(ReadOnlySpan<byte> bytes) => _reader.Append(bytes);

    /// <summary>Removes, authenticates and decrypts the next complete record.</summary>
    /// <returns>False until a complete record has arrived.</returns>
    public bool TryRead(out ContentType type, out byte[] plaintext)
    {
        type = ContentType.Invalid;
        plaintext = [];
        if (!_reader.TryRead(out var record)) return false;
        if (ReadProtection is null || PassesInPlaintext(record.Type))
        {
            if (record.Fragment.Length > TlsRecord.MaximumPlaintextLength)
                throw new TlsAlertException(TlsAlertDescription.RecordOverflow, TlsMessages.RecordTooLong);
            (type, plaintext) = (record.Type, record.Fragment);
            return true;
        }
        (type, plaintext) = ReadProtection.Unprotect(record, _readSequence++);
        return true;
    }

    /// <summary>Installs new keys for incoming records and restarts the read sequence number.</summary>
    public void SetReadProtection(RecordProtection? protection)
    {
        ReadProtection?.Dispose();
        ReadProtection = protection;
        _readSequence = 0;
    }

    /// <summary>
    /// Installs new keys for outgoing records and restarts the write sequence number. Handshake messages queued
    /// under the old keys are sent first, so they stay protected by the keys they were written for.
    /// </summary>
    public void SetWriteProtection(RecordProtection? protection)
    {
        FlushHandshake();
        WriteProtection?.Dispose();
        WriteProtection = protection;
        _writeSequence = 0;
    }

    /// <summary>Queues a complete handshake message; it is coalesced with the rest of its flight.</summary>
    public void QueueHandshake(ReadOnlySpan<byte> message) => _pendingHandshake.Write(message);

    /// <summary>Writes <paramref name="data"/> as one or more records of <paramref name="type"/>, after any queued handshake bytes.</summary>
    public void Write(ContentType type, ReadOnlySpan<byte> data)
    {
        FlushHandshake();
        WriteFragments(type, data);
    }

    /// <summary>
    /// Writes a ChangeCipherSpec record: the single byte 1. It is never encrypted. In TLS 1.2 it announces the key
    /// switch (RFC 5246 7.1); in TLS 1.3 it is a dummy that makes the handshake look like TLS 1.2 session
    /// resumption to middleboxes (RFC 8446 D.4).
    /// </summary>
    public void WriteChangeCipherSpec()
    {
        FlushHandshake();
        var header = TlsRecord.CreateHeader(ContentType.ChangeCipherSpec, WriteVersion, ChangeCipherSpecBody.Length);
        _output.Write(header);
        _output.Write(ChangeCipherSpecBody);
    }

    /// <summary>Sends queued handshake messages under the current write keys.</summary>
    public void FlushHandshake()
    {
        if (_pendingHandshake.WrittenCount == 0) return;
        var pending = _pendingHandshake.WrittenSpan.ToArray();
        _pendingHandshake.ResetWrittenCount();
        WriteFragments(ContentType.Handshake, pending);
    }

    /// <summary>Removes and returns every record written so far, ready for the transport.</summary>
    public byte[] TakeOutput()
    {
        FlushHandshake();
        var bytes = _output.WrittenSpan.ToArray();
        _output.ResetWrittenCount();
        return bytes;
    }

    /// <summary>
    /// TLS 1.3 exceptions to "everything is encrypted once keys exist": the compatibility ChangeCipherSpec is always
    /// plaintext (RFC 8446 5), and, while the handshake runs, so is an alert from a peer that never derived keys.
    /// Neither consumes a sequence number.
    /// </summary>
    private bool PassesInPlaintext(ContentType type) =>
        ReadProtection is Tls13RecordProtection &&
        (type == ContentType.ChangeCipherSpec || (type == ContentType.Alert && AcceptPlaintextAlerts));

    /// <summary>Splits <paramref name="data"/> at the fragment limit and seals each piece as the next record.</summary>
    private void WriteFragments(ContentType type, ReadOnlySpan<byte> data)
    {
        do
        {
            var chunk = data[..Math.Min(data.Length, MaximumFragmentLength)];
            data = data[chunk.Length..];
            if (WriteProtection is null)
            {
                _output.Write(TlsRecord.CreateHeader(type, WriteVersion, chunk.Length));
                _output.Write(chunk);
            }
            else
            {
                _output.Write(WriteProtection.Protect(type, chunk, _writeSequence++));
            }
        } while (!data.IsEmpty);
    }
}
