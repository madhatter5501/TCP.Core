namespace TCP.L5_7.Application.Tls;

/// <summary>
/// A TLS protocol version as it appears on the wire. TLS descends from SSL 3.0 (0x0300), so TLS 1.0 is "3.1",
/// TLS 1.2 is "3.3" and TLS 1.3 is "3.4".
/// </summary>
/// <remarks>
/// TLS 1.3 freezes the old version fields at 1.2 (the record header's <c>legacy_record_version</c> and the hellos'
/// <c>legacy_version</c>), because middleboxes broke when they saw a new number there. The real version is
/// negotiated in the supported_versions extension instead (RFC 8446 4.2.1).
/// </remarks>
public enum TlsVersion : ushort
{
    /// <summary>TLS 1.0 (RFC 2246). Not supported; appears only as the record version of a first ClientHello.</summary>
    Tls10 = 0x0301,
    /// <summary>TLS 1.2 (RFC 5246).</summary>
    Tls12 = 0x0303,
    /// <summary>TLS 1.3 (RFC 8446).</summary>
    Tls13 = 0x0304,
}
