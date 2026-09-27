using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Handshake.Messages;

/// <summary>
/// A signature together with the scheme that made it. It is the whole body of a TLS 1.3 CertificateVerify and the
/// tail of a TLS 1.2 ServerKeyExchange.
/// </summary>
/// <remarks>
/// <code>
/// struct { SignatureScheme algorithm; opaque signature&lt;0..2^16-1&gt;; } CertificateVerify;   // RFC 8446 4.4.3
/// digitally-signed struct { ... }  = SignatureAndHashAlgorithm + opaque signature&lt;0..2^16-1&gt;  // RFC 5246 4.7
/// </code>
/// </remarks>
internal readonly record struct DigitallySigned(TlsSignatureScheme Scheme, byte[] Signature)
{
    /// <summary>Appends the scheme and the length-prefixed signature.</summary>
    public void Write(TlsWriter writer)
    {
        writer.WriteUInt16((ushort)Scheme);
        writer.WriteVector16(Signature);
    }

    /// <summary>Reads a scheme and signature.</summary>
    public static DigitallySigned Read(ref TlsReader reader) =>
        new((TlsSignatureScheme)reader.ReadUInt16(), [.. reader.ReadVector16()]);

    /// <summary>A framed TLS 1.3 CertificateVerify message.</summary>
    public byte[] SerializeCertificateVerify()
    {
        var writer = new TlsWriter();
        Write(writer);
        return HandshakeMessage.Frame(HandshakeType.CertificateVerify, writer.WrittenSpan);
    }

    /// <summary>Parses a CertificateVerify body.</summary>
    public static DigitallySigned ParseCertificateVerify(ReadOnlySpan<byte> body)
    {
        var reader = new TlsReader(body);
        var signed = Read(ref reader);
        reader.EnsureEnd();
        return signed;
    }
}
