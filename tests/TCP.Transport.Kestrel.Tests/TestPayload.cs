namespace TCP.Transport.Kestrel.Tests;

/// <summary>Deterministic, non-repeating-looking bytes so misordered or duplicated data is detected.</summary>
internal static class TestPayload
{
    public static byte[] Create(int length)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++) bytes[i] = (byte)(i * 31 + (i >> 8) * 7 + 11);
        return bytes;
    }
}
