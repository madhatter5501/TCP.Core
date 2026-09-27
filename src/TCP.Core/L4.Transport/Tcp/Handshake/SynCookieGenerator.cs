using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using TCP.L3.Network.IPv4;

namespace TCP.L4.Transport.Tcp.Handshake;

/// <summary>What a valid SYN cookie restores about the SYN it answered.</summary>
/// <param name="MaximumSegmentSize">The peer's MSS, rounded down to the nearest table entry.</param>
/// <param name="Options">The options negotiated on the SYN, if timestamps carried them; null otherwise.</param>
internal readonly record struct SynCookie(ushort MaximumSegmentSize, SynCookieOptions? Options);

/// <summary>SYN options that fit in the low bits of a cookie SYN-ACK's timestamp.</summary>
/// <param name="PeerWindowScale">The peer's window scale shift, or null when it did not offer scaling.</param>
/// <param name="SackPermitted">Both sides agreed to SACK.</param>
/// <param name="ExplicitCongestionNotification">Both sides agreed to ECN.</param>
internal readonly record struct SynCookieOptions(byte? PeerWindowScale, bool SackPermitted, bool ExplicitCongestionNotification);

/// <summary>Stateless SYN-ACKs for a listener whose backlog is full (RFC 4987 3.6).</summary>
/// <remarks>
/// <para>
/// A SYN flood fills a listener's backlog with half-open connections that never complete, locking out real
/// clients. With SYN cookies the server keeps no state for a SYN at all. It encodes what it must remember in the
/// initial sequence number of its SYN-ACK: a 5-bit time counter, a 3-bit index into an MSS table, and a 24-bit keyed
/// hash of the four-tuple, the client's ISN and those fields. A genuine client's final ACK acknowledges ISN + 1, so
/// the server recomputes the hash, checks the counter is recent, and only then creates the connection.
/// </para>
/// <para>
/// The sequence number has no room for window scale, SACK or ECN. When the client supports timestamps, those
/// ride in the low 6 bits of the SYN-ACK's TSval and come back in the ACK's TSecr, as Linux does. Without
/// timestamps a cookie connection falls back to no window scaling, no SACK and no ECN.
/// </para>
/// </remarks>
/// <param name="time">Clock for the counter; tests substitute a fake one.</param>
internal sealed class SynCookieGenerator(TimeProvider time)
{
    private const int SecretBytes = 32;
    private const int CounterShift = 27;
    private const int MssIndexShift = 24;
    private const uint MssIndexMask = 0x7;
    private const uint CounterMask = 0x1F;
    private const uint HashMask = 0xFFFFFF;
    private const long CounterPeriodSeconds = 64;
    private const int MaximumCounterAge = 1; // A cookie stays valid for the current and previous period: 64-128 s.
    private const int TimestampOptionBits = 6;
    private const uint TimestampOptionMask = (1 << TimestampOptionBits) - 1;
    private const uint WindowScaleMask = 0xF;
    private const uint NoWindowScale = 0xF;
    private const uint SackBit = 0x10;
    private const uint EcnBit = 0x20;
    private const int HashInputLength = IPv4Packet.IPv4AddressLength * 2 + sizeof(ushort) * 2 + sizeof(uint) * 2 + 1;

    /// <summary>MSS values a cookie can express; a peer's MSS is rounded down to one of these.</summary>
    private static ReadOnlySpan<ushort> MssTable => [536, 1024, 1220, 1300, 1440, 1460, 4312, 8960];

    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(SecretBytes);

    /// <summary>The cookie to use as our ISN for a SYN from <paramref name="connection"/>.</summary>
    /// <param name="localAddress">Our address.</param>
    /// <param name="connection">The four-tuple the SYN arrived on.</param>
    /// <param name="peerInitialSequence">The SYN's sequence number.</param>
    /// <param name="peerMss">The SYN's MSS option, or the default when absent.</param>
    /// <param name="encodedMss">The MSS the cookie records, which the SYN-ACK should use as the peer's MSS.</param>
    public uint Create(IPAddress localAddress, ConnectionKey connection, uint peerInitialSequence, ushort peerMss, out ushort encodedMss)
    {
        var index = MssTable.Length - 1;
        while (index > 0 && MssTable[index] > peerMss) index--;
        encodedMss = MssTable[index];
        var counter = Counter();
        var hash = Hash(localAddress, connection, peerInitialSequence, counter, (uint)index);
        return counter << CounterShift | (uint)index << MssIndexShift | hash;
    }

    /// <summary>Checks the ACK that completes a cookie handshake.</summary>
    /// <param name="localAddress">Our address.</param>
    /// <param name="connection">The four-tuple the ACK arrived on.</param>
    /// <param name="peerInitialSequence">The client's ISN: the ACK's sequence number minus one.</param>
    /// <param name="cookie">Our ISN: the ACK's acknowledgment number minus one.</param>
    /// <param name="echoedTimestamp">The ACK's TSecr, which carries the SYN's options when timestamps were agreed.</param>
    /// <param name="result">The recovered MSS and options.</param>
    /// <returns>Whether the cookie is genuine and recent.</returns>
    public bool TryValidate(IPAddress localAddress, ConnectionKey connection, uint peerInitialSequence, uint cookie,
        uint? echoedTimestamp, out SynCookie result)
    {
        result = default;
        var counter = cookie >> CounterShift;
        var age = (Counter() - counter) & CounterMask;
        if (age > MaximumCounterAge) return false;
        var index = cookie >> MssIndexShift & MssIndexMask;
        var expected = Hash(localAddress, connection, peerInitialSequence, counter, index);
        if ((cookie & HashMask) != expected) return false;
        result = new SynCookie(MssTable[(int)index], echoedTimestamp is { } echo ? DecodeOptions(echo) : null);
        return true;
    }

    /// <summary>
    /// The TSval for a cookie SYN-ACK: the timestamp clock with its low 6 bits replaced by the options, stepped back
    /// one period if that would put it ahead of the clock.
    /// </summary>
    public static uint EncodeTimestamp(uint clock, SynCookieOptions options)
    {
        var bits = (options.PeerWindowScale is { } scale ? scale & WindowScaleMask : NoWindowScale)
            | (options.SackPermitted ? SackBit : 0) | (options.ExplicitCongestionNotification ? EcnBit : 0);
        var value = (clock & ~TimestampOptionMask) | bits;
        return unchecked((int)(value - clock)) > 0 ? value - (TimestampOptionMask + 1) : value;
    }

    /// <summary>The inverse of <see cref="EncodeTimestamp"/>: reads the options back from the low bits of the ACK's TSecr.</summary>
    private static SynCookieOptions DecodeOptions(uint echo)
    {
        var scale = echo & WindowScaleMask;
        return new SynCookieOptions(scale == NoWindowScale ? null : (byte)scale, (echo & SackBit) != 0, (echo & EcnBit) != 0);
    }

    /// <summary>The 5-bit time counter embedded in each cookie, advancing once per period; stale cookies fail the recency check.</summary>
    private uint Counter() => (uint)(time.GetUtcNow().ToUnixTimeSeconds() / CounterPeriodSeconds) & CounterMask;

    /// <summary>24 bits of HMAC-SHA256 over the four-tuple, the peer's ISN, the counter and the MSS index.</summary>
    private uint Hash(IPAddress localAddress, ConnectionKey connection, uint peerInitialSequence, uint counter, uint mssIndex)
    {
        var input = new byte[HashInputLength];
        var span = input.AsSpan();
        localAddress.GetAddressBytes().CopyTo(span);
        connection.RemoteAddress.GetAddressBytes().CopyTo(span[IPv4Packet.IPv4AddressLength..]);
        span = span[(IPv4Packet.IPv4AddressLength * 2)..];
        BinaryPrimitives.WriteUInt16BigEndian(span, connection.LocalPort);
        BinaryPrimitives.WriteUInt16BigEndian(span[sizeof(ushort)..], connection.RemotePort);
        BinaryPrimitives.WriteUInt32BigEndian(span[(sizeof(ushort) * 2)..], peerInitialSequence);
        BinaryPrimitives.WriteUInt32BigEndian(span[(sizeof(ushort) * 2 + sizeof(uint))..], counter);
        span[^1] = (byte)mssIndex;
        return BinaryPrimitives.ReadUInt32BigEndian(HMACSHA256.HashData(_secret, input)) & HashMask;
    }
}
