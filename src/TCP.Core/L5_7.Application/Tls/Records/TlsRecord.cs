using System.Buffers.Binary;

namespace TCP.L5_7.Application.Tls.Records;

/// <summary>
/// One record exactly as it crossed the wire: the 5-byte header and the fragment it announces.
/// </summary>
/// <remarks>
/// <code>
/// struct {
///     ContentType type;                  // 1 byte
///     ProtocolVersion legacy_record_version; // 2 bytes, 0x0303 (0x0301 allowed on a first ClientHello)
///     uint16 length;                     // fragment length
///     opaque fragment[length];
/// } TLSPlaintext;                        // RFC 8446 5.1
/// </code>
/// The header is also the additional authenticated data of a TLS 1.3 record (RFC 8446 5.2), so it is kept whole.
/// </remarks>
internal readonly record struct TlsRecord(byte[] Header, byte[] Fragment)
{
    /// <summary>Content type (1), legacy version (2) and length (2).</summary>
    public const int HeaderLength = 5;
    /// <summary>2^14: the largest plaintext fragment either version allows (RFC 8446 5.1, RFC 5246 6.2.1).</summary>
    public const int MaximumPlaintextLength = 16_384;
    /// <summary>TLS 1.3 allows 256 bytes of expansion for the content type, padding and AEAD tag (RFC 8446 5.2).</summary>
    public const int MaximumTls13CiphertextLength = MaximumPlaintextLength + 256;
    /// <summary>TLS 1.2 allows 2048 bytes of expansion (RFC 5246 6.2.3); the largest record either version accepts.</summary>
    public const int MaximumTls12CiphertextLength = MaximumPlaintextLength + 2048;

    /// <summary>The record's content type byte.</summary>
    public ContentType Type => (ContentType)Header[0];

    /// <summary>The legacy_record_version field.</summary>
    public ushort Version => BinaryPrimitives.ReadUInt16BigEndian(Header.AsSpan(1));

    /// <summary>Builds a record header announcing <paramref name="length"/> fragment bytes.</summary>
    public static byte[] CreateHeader(ContentType type, ushort version, int length)
    {
        var header = new byte[HeaderLength];
        header[0] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(1), version);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(3), checked((ushort)length));
        return header;
    }
}
