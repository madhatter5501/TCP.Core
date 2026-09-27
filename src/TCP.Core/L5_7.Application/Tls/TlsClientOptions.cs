using System.Security.Cryptography.X509Certificates;

namespace TCP.L5_7.Application.Tls;

/// <summary>Settings for the client end: which server to expect and how to judge its certificate, plus <see cref="TlsOptions"/>.</summary>
public sealed record TlsClientOptions : TlsOptions
{
    /// <summary>
    /// The server's host name. It is sent as Server Name Indication (unless it is an IP literal) and, with the
    /// default validation, must match the certificate.
    /// </summary>
    public string? TargetHost { get; init; }

    /// <summary>
    /// Decides whether the server's certificate (leaf, then the intermediates it sent) is acceptable. Null uses
    /// <see cref="TlsCertificates.ValidateServerCertificate"/>: a chain to a trusted root and a matching host name.
    /// </summary>
    public Func<X509Certificate2, X509Certificate2Collection, bool>? CertificateValidation { get; init; }

    /// <summary>
    /// TLS 1.3 middlebox compatibility mode (RFC 8446 D.4): send a random legacy_session_id and a dummy
    /// ChangeCipherSpec so the handshake looks like TLS 1.2 resumption to network devices that inspect it.
    /// </summary>
    public bool MiddleboxCompatibility { get; init; } = true;

    /// <summary>Sends this exact ClientHello message instead of building one, so a test can replay a published trace.</summary>
    internal byte[]? ClientHelloOverride { get; init; }
}
