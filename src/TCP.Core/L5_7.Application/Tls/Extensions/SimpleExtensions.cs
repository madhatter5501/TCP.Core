using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Extensions;

/// <summary>
/// Extensions whose bodies are a single small field: record_size_limit, cookie, ec_point_formats,
/// renegotiation_info and extended_master_secret.
/// </summary>
internal static class SimpleExtensions
{
    /// <summary>RFC 8449 4: a limit below 64 bytes is an illegal_parameter.</summary>
    public const int MinimumRecordSizeLimit = 64;
    private const byte UncompressedPointFormat = 0;

    /// <summary>
    /// record_size_limit (RFC 8449): the largest record plaintext the sender is willing to receive. In TLS 1.3 the
    /// value counts the inner content type byte, so "no smaller than usual" is 2^14 + 1.
    /// </summary>
    public static TlsExtension RecordSizeLimit(int limit)
    {
        var writer = new TlsWriter();
        writer.WriteUInt16(limit);
        return new TlsExtension(ExtensionType.RecordSizeLimit, writer.ToArray());
    }

    /// <summary>Reads a record_size_limit.</summary>
    public static int ParseRecordSizeLimit(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var limit = reader.ReadUInt16();
        reader.EnsureEnd();
        if (limit < MinimumRecordSizeLimit)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.RecordSizeLimitTooSmall);
        return limit;
    }

    /// <summary>
    /// cookie (RFC 8446 4.2.2): opaque bytes a server can put in a HelloRetryRequest and the client must echo in
    /// its second ClientHello; lets a server stay stateless across the retry.
    /// </summary>
    public static byte[] ParseCookie(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var cookie = reader.ReadVector16();
        reader.EnsureEnd();
        if (cookie.IsEmpty) throw new TlsAlertException(TlsAlertDescription.DecodeError, TlsMessages.InvalidList);
        return [.. cookie];
    }

    /// <summary>
    /// ec_point_formats (RFC 8422 5.1.2) listing only "uncompressed", the one format every TLS 1.2 ECC
    /// implementation must support and the only one RFC 8422 still allows.
    /// </summary>
    public static TlsExtension UncompressedPointFormats { get; } = new(ExtensionType.EcPointFormats, [1, UncompressedPointFormat]);

    /// <summary>A peer's ec_point_formats includes "uncompressed".</summary>
    public static bool AllowsUncompressedPoints(ReadOnlySpan<byte> data)
    {
        var reader = new TlsReader(data);
        var formats = reader.ReadVector8();
        reader.EnsureEnd();
        return formats.Contains(UncompressedPointFormat);
    }

    /// <summary>
    /// renegotiation_info (RFC 5746) on an initial handshake: an empty renegotiated_connection vector. It tells the
    /// peer we will never splice a renegotiation onto a connection it did not start, closing the 2009
    /// renegotiation attack. This implementation refuses renegotiation outright.
    /// </summary>
    public static TlsExtension InitialRenegotiationInfo { get; } = new(ExtensionType.RenegotiationInfo, [0]);

    /// <summary>A peer's renegotiation_info is the empty form required on an initial handshake.</summary>
    public static bool IsInitialRenegotiationInfo(ReadOnlySpan<byte> data) => data.SequenceEqual(InitialRenegotiationInfo.Data);

    /// <summary>extended_master_secret (RFC 7627): an empty body in both hellos.</summary>
    public static TlsExtension ExtendedMasterSecret { get; } = new(ExtensionType.ExtendedMasterSecret, []);
}
