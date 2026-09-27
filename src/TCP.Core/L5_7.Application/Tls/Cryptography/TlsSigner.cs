using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Produces the server's handshake signatures. The default signs with the certificate's private key; tests
/// substitute one that returns a recorded signature, because RSA-PSS and ECDSA signatures are randomized and could
/// not otherwise reproduce a published trace.
/// </summary>
internal abstract class TlsSigner
{
    /// <summary>Which certificate family the key belongs to, for choosing a TLS 1.2 cipher suite.</summary>
    public abstract ServerAuthentication KeyType { get; }

    /// <summary>Schemes this key can sign with under <paramref name="version"/>, best first.</summary>
    public abstract IReadOnlyList<TlsSignatureScheme> Schemes(TlsVersion version);

    /// <summary>Signs <paramref name="data"/> as <paramref name="scheme"/>.</summary>
    public abstract byte[] Sign(TlsSignatureScheme scheme, byte[] data);

    /// <summary>A signer for <paramref name="certificate"/>'s private key.</summary>
    /// <exception cref="ArgumentException">The certificate has no ECDSA or RSA private key.</exception>
    public static TlsSigner ForCertificate(X509Certificate2 certificate) => new CertificateKeySigner(certificate);

    /// <summary>Signs with an ECDSA or RSA private key taken from a certificate.</summary>
    private sealed class CertificateKeySigner : TlsSigner
    {
        private readonly AsymmetricAlgorithm _key;

        public CertificateKeySigner(X509Certificate2 certificate)
        {
            _key = (AsymmetricAlgorithm?)certificate.GetECDsaPrivateKey() ?? certificate.GetRSAPrivateKey()
                ?? throw new ArgumentException(TlsMessages.CertificateNeedsPrivateKey, nameof(certificate));
            KeyType = _key is ECDsa ? ServerAuthentication.Ecdsa : ServerAuthentication.Rsa;
        }

        public override ServerAuthentication KeyType { get; }

        public override IReadOnlyList<TlsSignatureScheme> Schemes(TlsVersion version) => TlsSignatures.SchemesFor(_key, version);

        public override byte[] Sign(TlsSignatureScheme scheme, byte[] data) => TlsSignatures.Sign(scheme, _key, data);
    }
}
