namespace TCP.Checksums;

/// <summary>
/// The Internet checksum (RFC 1071): the ones'-complement of the ones'-complement sum of 16-bit words. The IPv4
/// header, ICMP messages, and TCP segments (with a pseudo-header) are all protected by it.
/// </summary>
public static class InternetChecksum
{
    /// <summary>Checksum of <paramref name="data"/>, with the checksum field itself set to zero, ready to write into it.</summary>
    /// <remarks>An odd trailing byte is treated as padded with a zero byte.</remarks>
    public static ushort Compute(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var i = 0;
        for (; i + 1 < data.Length; i += 2)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
        }

        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
        }

        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    /// <summary>Verifies data that includes its checksum field: a correct checksum makes the whole sum come out to zero.</summary>
    public static bool IsValid(ReadOnlySpan<byte> data) => Compute(data) == 0;
}
