using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TCP.L5_7.Application.Tls;

/// <summary>Certificate helpers: a self-signed server certificate for experiments, and the default client check.</summary>
/// <remarks>
/// A certificate binds a public key to a name, signed by an issuer the client already trusts. A self-signed
/// certificate is its own issuer, so no client trusts it by default; tests accept it explicitly through
/// <see cref="TlsClientOptions.CertificateValidation"/>, typically by comparing thumbprints.
/// </remarks>
public static class TlsCertificates
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1"; // id-kp-serverAuth (RFC 5280 4.2.1.12)
    private static readonly TimeSpan ClockSkewAllowance = TimeSpan.FromDays(1);
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(365);

    /// <summary>
    /// Creates a self-signed ECDSA P-256 certificate for <paramref name="hostName"/>, with the private key attached:
    /// the key type the default TLS 1.3 suite and TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 expect.
    /// </summary>
    public static X509Certificate2 CreateSelfSigned(string hostName = "localhost")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(hostName);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthenticationOid)], critical: false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now - ClockSkewAllowance, now + DefaultLifetime);
    }

    /// <summary>
    /// The default client check: the chain builds to a trusted root (using the intermediates the server sent), the
    /// leaf is valid for server authentication, and it names <paramref name="hostName"/> (RFC 6125).
    /// Revocation is not checked, since this stack has no route to OCSP responders.
    /// </summary>
    public static bool ValidateServerCertificate(X509Certificate2 certificate, X509Certificate2Collection intermediates, string? hostName)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
        chain.ChainPolicy.ExtraStore.AddRange(intermediates);
        return chain.Build(certificate) && (hostName is null || certificate.MatchesHostname(hostName));
    }
}
