using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Alerts;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// Ephemeral elliptic-curve Diffie-Hellman over a NIST prime curve, using the platform's <see cref="ECDiffieHellman"/>.
/// </summary>
/// <remarks>
/// <para>
/// Public keys travel as uncompressed points (RFC 8446 4.2.8.2, RFC 8422 5.4.1): the byte 0x04, then the X and Y
/// coordinates as fixed-width big-endian integers. A P-256 key share is therefore 1 + 32 + 32 = 65 bytes.
/// </para>
/// <para>
/// The shared secret is the X coordinate of the product point, not the whole point (RFC 8446 7.4.2, RFC 8422
/// 5.10), which is what <see cref="ECDiffieHellman.DeriveRawSecretAgreement"/> returns. A peer's point must be on
/// the curve, or a malicious peer could learn bits of our private key from a point on a weaker curve; importing it
/// through <see cref="ECDiffieHellman"/> performs that validation.
/// </para>
/// </remarks>
internal sealed class EcdheKeyExchange : TlsKeyExchange
{
    private const byte UncompressedPointFormat = 0x04;

    private readonly ECDiffieHellman _key;
    private readonly ECCurve _curve;

    /// <summary>Generates a fresh key pair on the curve for <paramref name="group"/>.</summary>
    public EcdheKeyExchange(TlsNamedGroup group)
    {
        Group = group;
        _curve = CurveFor(group);
        _key = ECDiffieHellman.Create(_curve);
    }

    /// <summary>Uses a known key pair, for replaying published traces such as RFC 8448's.</summary>
    internal EcdheKeyExchange(TlsNamedGroup group, byte[] privateKey, byte[] publicKey)
    {
        Group = group;
        _curve = CurveFor(group);
        var (x, y) = SplitPoint(publicKey, CoordinateLength(group));
        _key = ECDiffieHellman.Create(new ECParameters { Curve = _curve, D = privateKey, Q = new ECPoint { X = x, Y = y } });
    }

    /// <inheritdoc/>
    public override TlsNamedGroup Group { get; }

    /// <inheritdoc/>
    public override byte[] PublicKey
    {
        get
        {
            var q = _key.ExportParameters(false).Q;
            return [UncompressedPointFormat, .. q.X!, .. q.Y!];
        }
    }

    /// <inheritdoc/>
    public override byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey)
    {
        var (x, y) = SplitPoint(peerPublicKey, CoordinateLength(Group));
        try
        {
            using var peer = ECDiffieHellman.Create(new ECParameters { Curve = _curve, Q = new ECPoint { X = x, Y = y } });
            return _key.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.InvalidKeyShare);
        }
    }

    /// <inheritdoc/>
    public override void Dispose() => _key.Dispose();

    /// <summary>The .NET curve for a TLS named group.</summary>
    private static ECCurve CurveFor(TlsNamedGroup group) => group switch
    {
        TlsNamedGroup.Secp256r1 => ECCurve.NamedCurves.nistP256,
        TlsNamedGroup.Secp384r1 => ECCurve.NamedCurves.nistP384,
        TlsNamedGroup.Secp521r1 => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(group)),
    };

    /// <summary>Bytes per coordinate: the field size rounded up to whole bytes (66 for P-521).</summary>
    private static int CoordinateLength(TlsNamedGroup group) => group switch
    {
        TlsNamedGroup.Secp256r1 => 32,
        TlsNamedGroup.Secp384r1 => 48,
        _ => 66,
    };

    /// <summary>Splits an uncompressed point into X and Y, rejecting any other encoding.</summary>
    private static (byte[] X, byte[] Y) SplitPoint(ReadOnlySpan<byte> point, int coordinateLength)
    {
        if (point.Length != 1 + 2 * coordinateLength || point[0] != UncompressedPointFormat)
            throw new TlsAlertException(TlsAlertDescription.IllegalParameter, TlsMessages.InvalidKeyShare);
        return ([.. point.Slice(1, coordinateLength)], [.. point.Slice(1 + coordinateLength)]);
    }
}
