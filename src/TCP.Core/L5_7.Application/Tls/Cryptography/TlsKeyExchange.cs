namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// One side's ephemeral Diffie-Hellman key pair for a single handshake.
/// </summary>
/// <remarks>
/// <para>
/// Each side generates a fresh private key, sends only the public key (TLS 1.3 key_share, TLS 1.2
/// ServerKeyExchange / ClientKeyExchange), and combines its private key with the peer's public key. Both arrive at
/// the same shared secret, which an eavesdropper who saw only the public keys cannot compute. Because the keys are
/// thrown away afterwards, recorded traffic stays safe even if the server's certificate key later leaks: forward
/// secrecy. See <see cref="Demos.FiniteFieldDiffieHellman"/> for the arithmetic with small numbers.
/// </para>
/// <para>
/// The handshake code asks an <see cref="TlsOptions.KeyExchangeFactory"/> for instances, so tests can substitute a
/// fixed key pair and replay a published trace.
/// </para>
/// </remarks>
internal abstract class TlsKeyExchange : IDisposable
{
    /// <summary>The group this key pair belongs to.</summary>
    public abstract TlsNamedGroup Group { get; }

    /// <summary>Our public key in the group's wire encoding.</summary>
    public abstract byte[] PublicKey { get; }

    /// <summary>Combines our private key with the peer's public key.</summary>
    /// <exception cref="Alerts.TlsAlertException">The peer's key is malformed or not a valid group element (illegal_parameter).</exception>
    public abstract byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey);

    /// <summary>Groups <see cref="Create"/> can produce, in this implementation's order of preference.</summary>
    public static IReadOnlyList<TlsNamedGroup> SupportedGroups { get; } =
        [TlsNamedGroup.Secp256r1, TlsNamedGroup.Secp384r1, TlsNamedGroup.Secp521r1];

    /// <summary>A fresh key pair in <paramref name="group"/>, or null if the group is not implemented.</summary>
    public static TlsKeyExchange? Create(TlsNamedGroup group) =>
        SupportedGroups.Contains(group) ? new EcdheKeyExchange(group) : null;

    /// <summary>Releases the private key.</summary>
    public virtual void Dispose() { }
}
