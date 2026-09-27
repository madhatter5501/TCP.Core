using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Authentication;

/// <summary>Signs and verifies one connection's segments with TCP-AO (RFC 5925, 5926) or an MD5 signature (RFC 2385).</summary>
/// <remarks>
/// <para>
/// TCP-AO never uses the master key directly. Each direction gets its own traffic key, derived with a KDF from
/// the master key and the connection's addresses, ports and initial sequence numbers, so keys differ per
/// connection and per direction. SYNs use keys whose peer ISN is zero, because the peer's ISN is not known yet.
/// </para>
/// <para>
/// The MAC covers a 32-bit sequence number extension (so a MAC cannot be replayed after the sequence space wraps),
/// the pseudo-header, the TCP header with its checksum and MAC zeroed, and the payload. It is truncated to 96
/// bits. Keys are chosen by KeyID; the peer's RNextKeyID tells us which of our keys it wants next, which is
/// how keys roll over on a live connection.
/// </para>
/// <para>MD5 is simpler: a digest over the pseudo-header, the header without options, the payload and the key.</para>
/// </remarks>
internal sealed class SegmentAuthenticator
{
    public const int MacLength = 12; // Both RFC 5926 MACs are truncated to 96 bits.
    private const byte KdfIteration = 1;
    private const int Sha1KeyBits = 160;
    private const int CmacKeyBits = 128;
    private const int CmacKeyLength = CmacKeyBits / 8;
    private static readonly byte[] KdfLabel = Encoding.ASCII.GetBytes("TCP-AO");

    private readonly IReadOnlyList<TcpAuthenticationKey> _keys;
    private readonly IPAddress _local;
    private readonly IPAddress _remote;
    private readonly ushort _localPort;
    private readonly ushort _remotePort;
    private readonly Dictionary<(TcpAuthenticationKey Key, bool Send, bool Syn), byte[]> _trafficKeys = [];
    private uint _localIsn;
    private uint _remoteIsn;

    /// <summary>Creates the authenticator for one connection; traffic keys are derived per key and direction as needed.</summary>
    /// <param name="keys">The keys that cover this connection; the first is used to send until the peer asks for another.</param>
    /// <param name="local">Our IPv4 address, part of the traffic-key derivation and the MAC's pseudo-header.</param>
    /// <param name="remote">The peer's IPv4 address.</param>
    /// <param name="localPort">Our port.</param>
    /// <param name="remotePort">The peer's port.</param>
    public SegmentAuthenticator(
        IReadOnlyList<TcpAuthenticationKey> keys, IPAddress local, IPAddress remote, ushort localPort, ushort remotePort)
    {
        _keys = keys;
        _local = local;
        _remote = remote;
        _localPort = localPort;
        _remotePort = remotePort;
        SendKey = keys[0];
    }

    /// <summary>The key we sign with.</summary>
    public TcpAuthenticationKey SendKey { get; private set; }

    /// <summary>Whether the connection uses the RFC 2385 MD5 option rather than TCP-AO.</summary>
    public bool UsesMd5 => SendKey.Algorithm == TcpAuthenticationAlgorithm.Md5;

    /// <summary>Bytes the signature option occupies once aligned.</summary>
    public int OptionLength => UsesMd5 ? TcpOptions.AlignedMd5Length : TcpWireFormat.OptionHeaderLength + 2 + MacLength;

    /// <summary>Records the initial sequence numbers that traffic keys are derived from; the peer's is 0 until its SYN arrives.</summary>
    public void SetInitialSequences(uint local, uint remote)
    {
        if (_localIsn == local && _remoteIsn == remote) return;
        (_localIsn, _remoteIsn) = (local, remote);
        _trafficKeys.Clear();
    }

    /// <summary>Adds a placeholder signature option to <paramref name="writer"/>.</summary>
    /// <returns>Where the MAC or digest begins in the options area, or null when the option did not fit.</returns>
    public int? AddOption(TcpOptionWriter writer)
    {
        var option = UsesMd5 ? TcpOptionWriter.Md5Signature()
            : TcpOptionWriter.Authentication(SendKey.SendId, SendKey.ReceiveId, MacLength);
        return writer.TryAdd(option) is { } offset ? offset + (UsesMd5 ? TcpWireFormat.OptionHeaderLength : 4) : null;
    }

    /// <summary>Fills in the signature of an outgoing segment whose options already hold the placeholder at <paramref name="macOffset"/>.</summary>
    /// <param name="segment">The segment to sign.</param>
    /// <param name="macOffset">Offset of the MAC within the options area, from <see cref="AddOption"/>.</param>
    /// <param name="sequenceExtension">The high 32 bits of the segment's 64-bit sequence number (TCP-AO's SNE).</param>
    public TcpSegment Sign(TcpSegment segment, int macOffset, uint sequenceExtension)
    {
        var mac = Compute(SendKey, send: true, segment, macOffset, _local, _remote, sequenceExtension);
        var options = segment.Options.ToArray();
        mac.CopyTo(options, macOffset);
        return segment with { Options = options };
    }

    /// <summary>
    /// Checks an arriving segment's signature, and follows the peer's request to switch our send key (RNextKeyID).
    /// A segment without the expected option, with an unknown KeyID or with a wrong MAC fails.
    /// </summary>
    public bool Verify(TcpSegment segment, TcpOptions options, uint sequenceExtension)
    {
        if (UsesMd5)
            return options.Md5DigestOffset is { } offset &&
                   CryptographicOperations.FixedTimeEquals(Compute(SendKey, send: false, segment, offset, _remote, _local, 0),
                       segment.Options.Span.Slice(offset, TcpOptions.Md5DigestLength));
        if (options.Authentication is not { } field) return false;
        var key = _keys.FirstOrDefault(k => k.ReceiveId == field.KeyId && k.Algorithm != TcpAuthenticationAlgorithm.Md5);
        if (key is null || field.Mac.Length != MacLength) return false;
        var expected = Compute(key, send: false, segment, field.MacOffset, _remote, _local, sequenceExtension);
        if (!CryptographicOperations.FixedTimeEquals(expected, field.Mac)) return false;
        if (field.NextKeyId != SendKey.SendId && _keys.FirstOrDefault(k => k.SendId == field.NextKeyId) is { } requested)
            SendKey = requested;
        return true;
    }

    /// <summary>The MAC or digest over the segment as it was, or will be, on the wire with the signature field zeroed.</summary>
    private byte[] Compute(
        TcpAuthenticationKey key, bool send, TcpSegment segment, int macOffset,
        IPAddress source, IPAddress destination, uint sequenceExtension)
    {
        var raw = segment.SerializeWithoutChecksum(source);
        var macLength = key.Algorithm == TcpAuthenticationAlgorithm.Md5 ? TcpOptions.Md5DigestLength : MacLength;
        raw.AsSpan(TcpWireFormat.MinimumHeaderLength + macOffset, Math.Min(macLength, segment.Options.Length - macOffset)).Clear();
        if (key.Algorithm == TcpAuthenticationAlgorithm.Md5) return Md5Digest(key, raw, segment.HeaderLength, source, destination);
        var covered = key.IncludeOptions ? raw : WithoutOtherOptions(raw, segment, macOffset);
        // The pseudo-header states the real segment length even when options are skipped.
        var pseudoHeader = PseudoHeader(source, destination, raw);
        var input = new byte[sizeof(uint) + pseudoHeader.Length + covered.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, sequenceExtension);
        pseudoHeader.CopyTo(input, sizeof(uint));
        covered.CopyTo(input, sizeof(uint) + pseudoHeader.Length);
        var trafficKey = TrafficKey(key, send, segment.Has(TcpFlags.Syn) && !segment.Has(TcpFlags.Ack));
        var mac = key.Algorithm == TcpAuthenticationAlgorithm.AesCmac128
            ? AesCmac.Compute(trafficKey, input)
            : HMACSHA1.HashData(trafficKey, input);
        return mac[..MacLength];
    }

    /// <summary>RFC 2385 2.0: MD5 over the pseudo-header, the 20-byte header with checksum zero, the payload and the key.</summary>
    private static byte[] Md5Digest(TcpAuthenticationKey key, byte[] raw, int headerLength, IPAddress source, IPAddress destination)
    {
        var pseudoHeader = PseudoHeader(source, destination, raw);
        // RFC 2385 2.0: pseudo-header, fixed TCP header (options excluded), payload, then the key.
        byte[] input =
            [.. pseudoHeader, .. raw.AsSpan(0, TcpWireFormat.MinimumHeaderLength), .. raw.AsSpan(headerLength), .. key.MasterKey];
        return MD5.HashData(input);
    }

    /// <summary>Just the pseudo-header for a segment of <paramref name="raw"/>'s length.</summary>
    private static byte[] PseudoHeader(IPAddress source, IPAddress destination, byte[] raw)
    {
        var withPseudo = TcpSegment.WithPseudoHeader(source, destination, raw);
        return withPseudo[..(withPseudo.Length - raw.Length)];
    }

    /// <summary>The header with every option except TCP-AO skipped, then the payload (RFC 5925 5.1, when options are excluded).</summary>
    private static byte[] WithoutOtherOptions(byte[] raw, TcpSegment segment, int macOffset)
    {
        var optionStart = macOffset - 4;
        var aoLength = 4 + MacLength;
        var payload = raw.AsSpan(segment.HeaderLength);
        var covered = new byte[TcpWireFormat.MinimumHeaderLength + aoLength + payload.Length];
        raw.AsSpan(0, TcpWireFormat.MinimumHeaderLength).CopyTo(covered);
        raw.AsSpan(TcpWireFormat.MinimumHeaderLength + optionStart, aoLength).CopyTo(covered.AsSpan(TcpWireFormat.MinimumHeaderLength));
        payload.CopyTo(covered.AsSpan(TcpWireFormat.MinimumHeaderLength + aoLength));
        return covered;
    }

    /// <summary>
    /// A traffic key (RFC 5925 5.2): the KDF over the sender's and receiver's addresses, ports and ISNs, with the
    /// receiver's ISN zero for a SYN.
    /// </summary>
    private byte[] TrafficKey(TcpAuthenticationKey key, bool send, bool syn)
    {
        if (_trafficKeys.TryGetValue((key, send, syn), out var cached)) return cached;
        var (source, destination) = send ? (_local, _remote) : (_remote, _local);
        var (sourcePort, destinationPort) = send ? (_localPort, _remotePort) : (_remotePort, _localPort);
        var (sourceIsn, destinationIsn) = send ? (_localIsn, _remoteIsn) : (_remoteIsn, _localIsn);
        if (syn) destinationIsn = 0;
        var sourceBytes = source.GetAddressBytes();
        var destinationBytes = destination.GetAddressBytes();
        var context = new byte[sourceBytes.Length + destinationBytes.Length + sizeof(ushort) * 2 + sizeof(uint) * 2];
        sourceBytes.CopyTo(context, 0);
        destinationBytes.CopyTo(context, sourceBytes.Length);
        var span = context.AsSpan(sourceBytes.Length + destinationBytes.Length);
        BinaryPrimitives.WriteUInt16BigEndian(span, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(span[sizeof(ushort)..], destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(span[(sizeof(ushort) * 2)..], sourceIsn);
        BinaryPrimitives.WriteUInt32BigEndian(span[(sizeof(ushort) * 2 + sizeof(uint))..], destinationIsn);
        var trafficKey = Derive(key, context);
        _trafficKeys[(key, send, syn)] = trafficKey;
        return trafficKey;
    }

    /// <summary>
    /// RFC 5926 3.1: T = PRF(K, i || "TCP-AO" || context || output length in bits). For AES-CMAC a master key that
    /// is not 128 bits is first reduced to one with CMAC under a zero key.
    /// </summary>
    internal static byte[] Derive(TcpAuthenticationKey key, ReadOnlySpan<byte> context)
    {
        var cmac = key.Algorithm == TcpAuthenticationAlgorithm.AesCmac128;
        var input = new byte[1 + KdfLabel.Length + context.Length + sizeof(ushort)];
        input[0] = KdfIteration;
        KdfLabel.CopyTo(input, 1);
        context.CopyTo(input.AsSpan(1 + KdfLabel.Length));
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(input.Length - sizeof(ushort)), (ushort)(cmac ? CmacKeyBits : Sha1KeyBits));
        if (!cmac) return HMACSHA1.HashData(key.MasterKey, input);
        var masterKey = key.MasterKey.Length == CmacKeyLength ? key.MasterKey : AesCmac.Compute(new byte[CmacKeyLength], key.MasterKey);
        return AesCmac.Compute(masterKey, input);
    }
}
