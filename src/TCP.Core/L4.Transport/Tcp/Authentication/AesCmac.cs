using System.Security.Cryptography;

namespace TCP.L4.Transport.Tcp.Authentication;

/// <summary>AES-CMAC (RFC 4493), used by TCP-AO's AES-128-CMAC-96 MAC and key derivation (RFC 5926).</summary>
/// <remarks>
/// .NET has no CMAC primitive, so this builds it from AES block encryption: derive two subkeys by doubling
/// E(K, 0) in GF(2^128), CBC-encrypt the message with a zero IV, and fold a subkey into the last block
/// (K1 when the last block is full, K2 after 10* padding when it is not).
/// </remarks>
internal static class AesCmac
{
    private const int BlockSize = 16;
    private const byte ReductionConstant = 0x87; // R_128 from RFC 4493 2.3.
    private const byte PaddingMarker = 0x80;

    /// <summary>The 16-byte CMAC of <paramref name="message"/> under the 128-bit <paramref name="key"/>.</summary>
    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        using var aes = Aes.Create();
        aes.Key = [.. key];
        var (k1, k2) = Subkeys(aes);
        var blocks = Math.Max(1, (message.Length + BlockSize - 1) / BlockSize);
        var lastComplete = message.Length > 0 && message.Length % BlockSize == 0;
        var last = new byte[BlockSize];
        var lastStart = (blocks - 1) * BlockSize;
        message[lastStart..].CopyTo(last);
        if (!lastComplete) last[message.Length - lastStart] = PaddingMarker;
        Xor(last, lastComplete ? k1 : k2);
        var state = new byte[BlockSize];
        for (var i = 0; i < blocks - 1; i++)
        {
            Xor(state, message.Slice(i * BlockSize, BlockSize));
            state = aes.EncryptEcb(state, PaddingMode.None);
        }
        Xor(state, last);
        return aes.EncryptEcb(state, PaddingMode.None);
    }

    /// <summary>RFC 4493 2.3: L = E(K, 0); K1 = L &lt;&lt; 1 (reduced); K2 = K1 &lt;&lt; 1 (reduced).</summary>
    private static (byte[] K1, byte[] K2) Subkeys(Aes aes)
    {
        var l = aes.EncryptEcb(new byte[BlockSize], PaddingMode.None);
        var k1 = Double(l);
        return (k1, Double(k1));
    }

    /// <summary>Multiplies by x in GF(2^128): shift left one bit, and if a bit fell off, XOR in the reduction constant.</summary>
    private static byte[] Double(byte[] block)
    {
        var result = new byte[BlockSize];
        for (var i = 0; i < BlockSize; i++)
            result[i] = (byte)(block[i] << 1 | (i + 1 < BlockSize ? block[i + 1] >> 7 : 0));
        if ((block[0] & PaddingMarker) != 0) result[BlockSize - 1] ^= ReductionConstant;
        return result;
    }

    /// <summary>XORs <paramref name="other"/> into <paramref name="target"/> byte by byte, over the length of <paramref name="target"/>.</summary>
    private static void Xor(Span<byte> target, ReadOnlySpan<byte> other)
    {
        for (var i = 0; i < target.Length; i++) target[i] ^= other[i];
    }
}
