using System.Security.Cryptography;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.L5_7.Application.Tls.Cryptography;

/// <summary>
/// The TLS 1.3 key schedule (RFC 8446 7.1): how one Diffie-Hellman shared secret becomes every key of the
/// connection.
/// </summary>
/// <remarks>
/// <para>
/// Everything is built from HKDF (RFC 5869). HKDF-Extract condenses input keying material into a pseudorandom
/// key; HKDF-Expand stretches a key into as many labelled outputs as needed. TLS wraps Expand so every output is
/// bound to a purpose and to the handshake so far:
/// <code>
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///     struct { uint16 length = Length; opaque label&lt;7..255&gt; = "tls13 " + Label; opaque context&lt;0..255&gt; = Context; } HkdfLabel;
/// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
/// </code>
/// </para>
/// <para>
/// The schedule is a chain of three extractions, each salted with a "derived" secret from the previous stage:
/// <code>
///            0 (no PSK)
///            |
///  0 -> HKDF-Extract = Early Secret
///            |
///      Derive-Secret(., "derived", "")
///            v
/// (EC)DHE -> HKDF-Extract = Handshake Secret --> "c hs traffic", "s hs traffic" over ClientHello..ServerHello
///            |
///      Derive-Secret(., "derived", "")
///            v
///  0 -> HKDF-Extract = Master Secret --> "c ap traffic", "s ap traffic", "exp master" over ClientHello..server Finished
///                                    --> "res master" over ClientHello..client Finished
/// </code>
/// Each traffic secret then yields a record key and IV (RFC 8446 7.3) and a Finished key (RFC 8446 4.4.4).
/// </para>
/// </remarks>
internal sealed class Tls13KeySchedule
{
    private const string LabelPrefix = "tls13 ";
    private const string DerivedLabel = "derived";
    private const string ClientHandshakeLabel = "c hs traffic";
    private const string ServerHandshakeLabel = "s hs traffic";
    private const string ClientApplicationLabel = "c ap traffic";
    private const string ServerApplicationLabel = "s ap traffic";
    private const string ExporterLabel = "exp master";
    private const string ResumptionLabel = "res master";
    private const string KeyLabel = "key";
    private const string IvLabel = "iv";
    private const string FinishedLabel = "finished";
    private const string KeyUpdateLabel = "traffic upd";

    private readonly byte[] _zeros;
    private readonly byte[] _emptyHash;

    /// <summary>Starts a schedule for a suite whose hash is <paramref name="hash"/>, computing the Early Secret.</summary>
    public Tls13KeySchedule(HashAlgorithmName hash)
    {
        Hash = hash;
        HashLength = CipherSuiteInfo.HashLengthOf(hash);
        _zeros = new byte[HashLength];
        _emptyHash = CryptographicOperations.HashData(hash, []);
        // Without a pre-shared key both the salt and the input keying material are a string of zeros.
        EarlySecret = HKDF.Extract(hash, _zeros, _zeros);
    }

    /// <summary>The suite's hash.</summary>
    public HashAlgorithmName Hash { get; }

    /// <summary>Output length of the hash; every secret has this length.</summary>
    public int HashLength { get; }

    /// <summary>First stage: HKDF-Extract(0, 0) when no PSK is used.</summary>
    public byte[] EarlySecret { get; }

    /// <summary>Second stage, mixing in the (EC)DHE shared secret; set by <see cref="DeriveHandshakeSecret"/>.</summary>
    public byte[]? HandshakeSecret { get; private set; }

    /// <summary>Third stage, from which application secrets come; set by <see cref="DeriveMasterSecret"/>.</summary>
    public byte[]? MasterSecret { get; private set; }

    /// <summary>Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), (EC)DHE).</summary>
    public void DeriveHandshakeSecret(byte[] sharedSecret) =>
        HandshakeSecret = HKDF.Extract(Hash, sharedSecret, DeriveSecret(EarlySecret, DerivedLabel, _emptyHash));

    /// <summary>Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0).</summary>
    public void DeriveMasterSecret() =>
        MasterSecret = HKDF.Extract(Hash, _zeros, DeriveSecret(Required(HandshakeSecret), DerivedLabel, _emptyHash));

    /// <summary>client_handshake_traffic_secret, over ClientHello..ServerHello.</summary>
    public byte[] ClientHandshakeTrafficSecret(byte[] transcriptHash) =>
        DeriveSecret(Required(HandshakeSecret), ClientHandshakeLabel, transcriptHash);

    /// <summary>server_handshake_traffic_secret, over ClientHello..ServerHello.</summary>
    public byte[] ServerHandshakeTrafficSecret(byte[] transcriptHash) =>
        DeriveSecret(Required(HandshakeSecret), ServerHandshakeLabel, transcriptHash);

    /// <summary>client_application_traffic_secret_0, over ClientHello..server Finished.</summary>
    public byte[] ClientApplicationTrafficSecret(byte[] transcriptHash) =>
        DeriveSecret(Required(MasterSecret), ClientApplicationLabel, transcriptHash);

    /// <summary>server_application_traffic_secret_0, over ClientHello..server Finished.</summary>
    public byte[] ServerApplicationTrafficSecret(byte[] transcriptHash) =>
        DeriveSecret(Required(MasterSecret), ServerApplicationLabel, transcriptHash);

    /// <summary>exporter_master_secret (RFC 8446 7.5), over ClientHello..server Finished.</summary>
    public byte[] ExporterMasterSecret(byte[] transcriptHash) => DeriveSecret(Required(MasterSecret), ExporterLabel, transcriptHash);

    /// <summary>resumption_master_secret, over ClientHello..client Finished; the root of session tickets.</summary>
    public byte[] ResumptionMasterSecret(byte[] transcriptHash) => DeriveSecret(Required(MasterSecret), ResumptionLabel, transcriptHash);

    /// <summary>RFC 8446 7.3: write_key = HKDF-Expand-Label(Secret, "key", "", key_length); write_iv likewise with "iv".</summary>
    public (byte[] Key, byte[] Iv) TrafficKeys(byte[] trafficSecret, CipherSuiteInfo suite) =>
        (ExpandLabel(Hash, trafficSecret, KeyLabel, [], suite.KeyLength),
         ExpandLabel(Hash, trafficSecret, IvLabel, [], suite.IvLength));

    /// <summary>
    /// RFC 8446 4.4.4: verify_data = HMAC(finished_key, Transcript-Hash(...)), where
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) and BaseKey is the sender's handshake
    /// traffic secret. Proves the sender saw the same transcript and holds the handshake keys.
    /// </summary>
    public byte[] FinishedVerifyData(byte[] handshakeTrafficSecret, byte[] transcriptHash) =>
        CryptographicOperations.HmacData(Hash, ExpandLabel(Hash, handshakeTrafficSecret, FinishedLabel, [], HashLength), transcriptHash);

    /// <summary>RFC 8446 7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length).</summary>
    public byte[] NextTrafficSecret(byte[] trafficSecret) => ExpandLabel(Hash, trafficSecret, KeyUpdateLabel, [], HashLength);

    /// <summary>Derive-Secret(Secret, Label, Messages), given the transcript hash of Messages.</summary>
    public byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash) =>
        ExpandLabel(Hash, secret, label, transcriptHash, HashLength);

    /// <summary>HKDF-Expand-Label: HKDF-Expand with the encoded <see cref="HkdfLabel"/> as its info.</summary>
    public static byte[] ExpandLabel(HashAlgorithmName hash, byte[] secret, string label, ReadOnlySpan<byte> context, int length) =>
        HKDF.Expand(hash, secret, length, HkdfLabel(label, context, length));

    /// <summary>The HkdfLabel structure: uint16 length, "tls13 " + label as a vector8, context as a vector8.</summary>
    public static byte[] HkdfLabel(string label, ReadOnlySpan<byte> context, int length)
    {
        var writer = new TlsWriter();
        writer.WriteUInt16(length);
        writer.WriteVector8(System.Text.Encoding.ASCII.GetBytes(LabelPrefix + label));
        writer.WriteVector8(context);
        return writer.ToArray();
    }

    /// <summary>The stage's secret, which must already have been derived.</summary>
    private static byte[] Required(byte[]? secret) => secret ?? throw new InvalidOperationException(TlsMessages.KeyScheduleOrder);
}
