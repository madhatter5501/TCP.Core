using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// What the TLS 1.3 client and server share: the key schedule, the traffic secrets it yields, and post-handshake
/// KeyUpdate (RFC 8446 4.6.3).
/// </summary>
/// <remarks>
/// A TLS 1.3 handshake moves each direction through three sets of keys: none for the hellos, handshake traffic keys
/// for the rest of the handshake, application traffic keys afterwards. KeyUpdate adds more generations: each side
/// can replace its sending keys at any time by deriving the next secret from the current one. That limits how much
/// data one key protects and means a key stolen later cannot decrypt earlier traffic.
/// </remarks>
internal abstract class Tls13Handshake(TlsEngine engine, CipherSuiteInfo suite) : HandshakeProtocol(engine)
{
    private byte[]? _readSecret;
    private byte[]? _writeSecret;

    /// <summary>The negotiated suite.</summary>
    protected CipherSuiteInfo Suite { get; } = suite;

    /// <summary>The key schedule, which tests read to compare secrets with RFC 8448.</summary>
    internal Tls13KeySchedule Schedule { get; } = new(suite.Hash);

    /// <summary>client_handshake_traffic_secret.</summary>
    internal byte[]? ClientHandshakeSecret { get; private protected set; }

    /// <summary>server_handshake_traffic_secret.</summary>
    internal byte[]? ServerHandshakeSecret { get; private protected set; }

    /// <summary>client_application_traffic_secret_0.</summary>
    internal byte[]? ClientApplicationSecret { get; private protected set; }

    /// <summary>server_application_traffic_secret_0.</summary>
    internal byte[]? ServerApplicationSecret { get; private protected set; }

    /// <summary>Transcript-Hash of every handshake message so far.</summary>
    protected byte[] TranscriptHash() => Engine.Transcript.Hash(Suite.Hash);

    /// <summary>After ServerHello: derive the Handshake Secret and both handshake traffic secrets (RFC 8446 7.1).</summary>
    protected void DeriveHandshakeSecrets(byte[] sharedSecret)
    {
        Schedule.DeriveHandshakeSecret(sharedSecret);
        var hash = TranscriptHash(); // ClientHello..ServerHello
        ClientHandshakeSecret = Schedule.ClientHandshakeTrafficSecret(hash);
        ServerHandshakeSecret = Schedule.ServerHandshakeTrafficSecret(hash);
    }

    /// <summary>After the server's Finished: derive the Master Secret and both application traffic secrets.</summary>
    protected void DeriveApplicationSecrets()
    {
        Schedule.DeriveMasterSecret();
        var hash = TranscriptHash(); // ClientHello..server Finished
        ClientApplicationSecret = Schedule.ClientApplicationTrafficSecret(hash);
        ServerApplicationSecret = Schedule.ServerApplicationTrafficSecret(hash);
        var server = Engine.IsServer;
        _readSecret = server ? ClientApplicationSecret : ServerApplicationSecret;
        _writeSecret = server ? ServerApplicationSecret : ClientApplicationSecret;
    }

    /// <summary>Record protection for a traffic secret: its derived key and IV with the suite's AEAD.</summary>
    protected RecordProtection Protection(byte[] trafficSecret)
    {
        var (key, iv) = Schedule.TrafficKeys(trafficSecret, Suite);
        return new Tls13RecordProtection(Suite, key, iv);
    }

    /// <summary>The Finished verify_data for the side whose handshake traffic secret is <paramref name="secret"/>.</summary>
    protected byte[] FinishedVerifyData(byte[] secret) => Schedule.FinishedVerifyData(secret, TranscriptHash());

    /// <summary>
    /// Honors a peer's record_size_limit (RFC 8449 4): its value counts the inner content type byte, so the largest
    /// plaintext we may send is one less.
    /// </summary>
    protected void ApplyPeerRecordSizeLimit(int limit) =>
        Engine.Records.MaximumFragmentLength = Math.Min(TlsRecord.MaximumPlaintextLength, limit - 1);

    /// <inheritdoc/>
    public override void OnPostHandshakeMessage(HandshakeMessage message)
    {
        switch (message.Type)
        {
            case HandshakeType.KeyUpdate:
                // RFC 8446 4.6.3: the peer now sends under its next secret; follow it. If it asked us to update as
                // well, reply with our own KeyUpdate so that both directions have moved on.
                var requested = SimpleMessages.ParseKeyUpdate(message.Body);
                _readSecret = Schedule.NextTrafficSecret(_readSecret!);
                Engine.SetReadProtection(Protection(_readSecret));
                Engine.KeyUpdatesReceived++;
                if (requested && !Engine.CloseNotifySent) SendKeyUpdate(requestPeerUpdate: false);
                break;
            case HandshakeType.NewSessionTicket when !Engine.IsServer:
                break; // Tickets allow resumption, which this implementation does not do.
            default:
                throw Unexpected(message);
        }
    }

    /// <summary>Sends KeyUpdate under the current keys, then switches our sending keys to the next generation.</summary>
    public void SendKeyUpdate(bool requestPeerUpdate)
    {
        Engine.SendPostHandshake(SimpleMessages.KeyUpdate(requestPeerUpdate));
        _writeSecret = Schedule.NextTrafficSecret(_writeSecret!);
        Engine.SetWriteProtection(Protection(_writeSecret));
    }
}
