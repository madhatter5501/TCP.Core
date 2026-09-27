using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace TCP.L5_7.Application.Tls.Demos;

/// <summary>
/// Classic finite-field Diffie-Hellman (1976) in a few lines of <see cref="BigInteger"/> arithmetic, to show the
/// idea behind TLS key exchange. A teaching aid only: TLS here uses the platform's elliptic-curve implementation,
/// and nothing in this class is constant-time.
/// </summary>
/// <remarks>
/// <para>
/// Both sides agree on a public prime p and generator g. Each picks a secret exponent, publishes g raised to it,
/// and raises the other's public value to its own secret:
/// <code>
/// Alice: secret a, sends A = g^a mod p          Bob: secret b, sends B = g^b mod p
/// Alice: s = B^a = g^(ba) mod p                 Bob:  s = A^b = g^(ab) mod p      (the same number)
/// </code>
/// An eavesdropper sees p, g, A and B but would need a or b, and recovering an exponent from g^a mod p (the
/// discrete logarithm problem) is infeasible for well-chosen 2048-bit primes. With the textbook toy group p = 23,
/// g = 5: a = 6 gives A = 8, b = 15 gives B = 19, and both reach s = 2.
/// </para>
/// <para>
/// Elliptic-curve Diffie-Hellman is the same protocol in a different group: "multiply a point by a secret scalar"
/// replaces "raise g to a secret power". The group is harder to attack per bit, so a 256-bit curve matches roughly a
/// 3072-bit prime. TLS 1.3 still allows finite-field groups (RFC 7919's ffdhe2048 and larger), shown by
/// <see cref="Ffdhe2048"/>.
/// </para>
/// <para>
/// A received public value must be checked: 1 and p - 1 generate tiny subgroups, so a peer sending them would
/// force the shared secret to a guessable value (RFC 7919 5.1).
/// </para>
/// </remarks>
public static class FiniteFieldDiffieHellman
{
    private const int Ffdhe2048Generator = 2;
    private const int ToyPrime = 23;
    private const int ToyGenerator = 5;

    /// <summary>The public parameters: prime modulus and generator.</summary>
    /// <param name="Name">A label for display.</param>
    /// <param name="Prime">The modulus p.</param>
    /// <param name="Generator">The base g.</param>
    public sealed record Group(string Name, BigInteger Prime, BigInteger Generator);

    /// <summary>The textbook example, small enough to check by hand. Offers no security.</summary>
    public static Group Toy { get; } = new("toy", ToyPrime, ToyGenerator);

    /// <summary>
    /// RFC 7919 A.1 ffdhe2048: a 2048-bit safe prime (p = 2q + 1 with q prime) derived from the digits of e, so
    /// nobody could have chosen it to hide a trapdoor. Generator 2.
    /// </summary>
    public static Group Ffdhe2048 { get; } = new("ffdhe2048", BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8" +
        "F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE872" +
        "1DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
        "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005" +
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", NumberStyles.HexNumber), Ffdhe2048Generator);

    /// <summary>One side of the exchange.</summary>
    public sealed class Party
    {
        /// <summary>Picks a random secret exponent in [2, p - 2], or uses <paramref name="privateKey"/> for a worked example.</summary>
        public Party(Group group, BigInteger? privateKey = null)
        {
            Group = group;
            PrivateKey = privateKey ?? RandomExponent(group.Prime);
            PublicKey = BigInteger.ModPow(group.Generator, PrivateKey, group.Prime);
        }

        /// <summary>The agreed public parameters.</summary>
        public Group Group { get; }

        /// <summary>The secret exponent: never sent.</summary>
        public BigInteger PrivateKey { get; }

        /// <summary>g^secret mod p: sent to the peer in the clear.</summary>
        public BigInteger PublicKey { get; }

        /// <summary>The peer's public value raised to our secret: the shared secret.</summary>
        /// <exception cref="ArgumentOutOfRangeException">The peer's value is outside 2..p-2.</exception>
        public BigInteger ComputeSharedSecret(BigInteger peerPublicKey)
        {
            if (peerPublicKey <= BigInteger.One || peerPublicKey >= Group.Prime - BigInteger.One)
                throw new ArgumentOutOfRangeException(nameof(peerPublicKey), TlsMessages.InvalidKeyShare);
            return BigInteger.ModPow(peerPublicKey, PrivateKey, Group.Prime);
        }
    }

    /// <summary>A uniformly random integer in [2, p - 2], by rejection sampling.</summary>
    private static BigInteger RandomExponent(BigInteger prime)
    {
        var bytes = new byte[prime.GetByteCount(isUnsigned: true)];
        while (true)
        {
            RandomNumberGenerator.Fill(bytes);
            var candidate = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            if (candidate >= 2 && candidate <= prime - 2) return candidate;
        }
    }
}
