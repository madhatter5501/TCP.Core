using System.Security.Cryptography.X509Certificates;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;

namespace TCP.L5_7.Application.Tls;

/// <summary>Settings for the server end: the certificate that proves the server's identity, plus <see cref="TlsOptions"/>.</summary>
/// <remarks>
/// <see cref="TlsCertificates.CreateSelfSigned"/> makes a suitable ECDSA P-256 certificate for experiments. The
/// server signs with the certificate's private key; which TLS 1.2 suites are usable depends on its type (ECDSA or
/// RSA).
/// </remarks>
public sealed record TlsServerOptions : TlsOptions
{
    /// <summary>The server's certificate, which must carry its private key.</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Intermediate certificates sent after <see cref="Certificate"/>, toward the client's trusted root.</summary>
    public X509Certificate2Collection? CertificateChain { get; init; }

    /// <summary>Replaces signing with the certificate's key; tests replay recorded signatures with it.</summary>
    internal TlsSigner? Signer { get; init; }

    /// <summary>Extra EncryptedExtensions entries placed first, so a test can reproduce a published server's exact message.</summary>
    internal IReadOnlyList<TlsExtension> AdditionalEncryptedExtensions { get; init; } = [];
}
