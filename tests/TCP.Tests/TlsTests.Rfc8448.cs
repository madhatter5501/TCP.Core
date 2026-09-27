using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TCP.L5_7.Application.Tls;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;

namespace TCP.Tests;

/// <summary>
/// TLS 1.3 checked byte for byte against RFC 8448's example traces: key schedule, transcript hash, record
/// protection, message encoding, and whole server and client flights replayed through <see cref="TlsEngine"/>.
/// </summary>
/// <remarks>
/// The traces use x25519 (which .NET lacks on macOS) and a randomized RSA-PSS signature, so the replay substitutes
/// a key exchange that returns the trace's shared secret and a signer that returns the trace's signature. Everything
/// else, from hello parsing to the AEAD, is the implementation's own.
/// </remarks>
internal static partial class TlsTests
{
    private static readonly CipherSuiteInfo Aes128Sha256 = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);

    private static void RunRfc8448Tests(Action<string, Action> test)
    {
        test("RFC 8448 3: key schedule and transcript hashes match byte for byte", () =>
        {
            var schedule = new Tls13KeySchedule(HashAlgorithmName.SHA256);
            Check(schedule.EarlySecret.SequenceEqual(Rfc8448.EarlySecret), "Early Secret");
            Check(Tls13KeySchedule.HkdfLabel("c hs traffic", Rfc8448.HelloHash, 32).SequenceEqual(Rfc8448.ClientHandshakeLabelInfo), "HkdfLabel encoding");
            Check(schedule.DeriveSecret(schedule.EarlySecret, "derived", SHA256.HashData([])).SequenceEqual(Rfc8448.DerivedForHandshake), "Derive-Secret(derived)");
            schedule.DeriveHandshakeSecret(Rfc8448.SharedSecret);
            Check(schedule.HandshakeSecret!.SequenceEqual(Rfc8448.HandshakeSecret), "Handshake Secret");

            var transcript = new TranscriptHash();
            transcript.Add(Rfc8448.ClientHello);
            transcript.Add(Rfc8448.ServerHello);
            var helloHash = transcript.Hash(HashAlgorithmName.SHA256);
            Check(helloHash.SequenceEqual(Rfc8448.HelloHash), "Transcript-Hash(ClientHello..ServerHello)");
            var clientHandshake = schedule.ClientHandshakeTrafficSecret(helloHash);
            var serverHandshake = schedule.ServerHandshakeTrafficSecret(helloHash);
            Check(clientHandshake.SequenceEqual(Rfc8448.ClientHandshakeTrafficSecret), "client_handshake_traffic_secret");
            Check(serverHandshake.SequenceEqual(Rfc8448.ServerHandshakeTrafficSecret), "server_handshake_traffic_secret");
            CheckKeys(schedule.TrafficKeys(serverHandshake, Aes128Sha256), Rfc8448.ServerHandshakeKey, Rfc8448.ServerHandshakeIv, "server handshake");
            CheckKeys(schedule.TrafficKeys(clientHandshake, Aes128Sha256), Rfc8448.ClientHandshakeKey, Rfc8448.ClientHandshakeIv, "client handshake");

            transcript.Add(Rfc8448.EncryptedExtensions);
            transcript.Add(Rfc8448.Certificate);
            transcript.Add(Rfc8448.CertificateVerify);
            Check(schedule.FinishedVerifyData(serverHandshake, transcript.Hash(HashAlgorithmName.SHA256))
                .SequenceEqual(Rfc8448.ServerFinished[HandshakeMessage.HeaderLength..]), "server Finished verify_data");
            transcript.Add(Rfc8448.ServerFinished);
            var finishedHash = transcript.Hash(HashAlgorithmName.SHA256);
            Check(finishedHash.SequenceEqual(Rfc8448.ServerFinishedHash), "Transcript-Hash(ClientHello..server Finished)");
            schedule.DeriveMasterSecret();
            Check(schedule.MasterSecret!.SequenceEqual(Rfc8448.MasterSecret), "Master Secret");
            var clientApplication = schedule.ClientApplicationTrafficSecret(finishedHash);
            var serverApplication = schedule.ServerApplicationTrafficSecret(finishedHash);
            Check(clientApplication.SequenceEqual(Rfc8448.ClientApplicationTrafficSecret), "client_application_traffic_secret_0");
            Check(serverApplication.SequenceEqual(Rfc8448.ServerApplicationTrafficSecret), "server_application_traffic_secret_0");
            Check(schedule.ExporterMasterSecret(finishedHash).SequenceEqual(Rfc8448.ExporterMasterSecret), "exporter_master_secret");
            CheckKeys(schedule.TrafficKeys(serverApplication, Aes128Sha256), Rfc8448.ServerApplicationKey, Rfc8448.ServerApplicationIv, "server application");
            CheckKeys(schedule.TrafficKeys(clientApplication, Aes128Sha256), Rfc8448.ClientApplicationKey, Rfc8448.ClientApplicationIv, "client application");

            Check(schedule.FinishedVerifyData(clientHandshake, finishedHash)
                .SequenceEqual(Rfc8448.ClientFinished[HandshakeMessage.HeaderLength..]), "client Finished verify_data");
            transcript.Add(Rfc8448.ClientFinished);
            var clientFinishedHash = transcript.Hash(HashAlgorithmName.SHA256);
            Check(clientFinishedHash.SequenceEqual(Rfc8448.ClientFinishedHash), "Transcript-Hash(ClientHello..client Finished)");
            Check(schedule.ResumptionMasterSecret(clientFinishedHash).SequenceEqual(Rfc8448.ResumptionMasterSecret), "resumption_master_secret");
        });
        test("RFC 8448 3: AEAD record protection reproduces every encrypted record", () =>
        {
            Check(Rfc8448.ServerFlightPayload.SequenceEqual([.. Rfc8448.EncryptedExtensions, .. Rfc8448.Certificate,
                .. Rfc8448.CertificateVerify, .. Rfc8448.ServerFinished]), "Trace flight is not the four messages");
            using var serverHandshake = new Tls13RecordProtection(Aes128Sha256, Rfc8448.ServerHandshakeKey, Rfc8448.ServerHandshakeIv);
            Check(serverHandshake.Protect(ContentType.Handshake, Rfc8448.ServerFlightPayload, 0).SequenceEqual(Rfc8448.ServerFlightRecord), "Server flight record");
            using var clientHandshake = new Tls13RecordProtection(Aes128Sha256, Rfc8448.ClientHandshakeKey, Rfc8448.ClientHandshakeIv);
            Check(clientHandshake.Protect(ContentType.Handshake, Rfc8448.ClientFinished, 0).SequenceEqual(Rfc8448.ClientFinishedRecord), "Client Finished record");
            using var client = new Tls13RecordProtection(Aes128Sha256, Rfc8448.ClientApplicationKey, Rfc8448.ClientApplicationIv);
            Check(client.Protect(ContentType.ApplicationData, Rfc8448.ApplicationPayload, 0).SequenceEqual(Rfc8448.ClientApplicationRecord), "Client data record");
            Check(client.Protect(ContentType.Alert, [1, 0], 1).SequenceEqual(Rfc8448.ClientAlertRecord), "Client close_notify record (sequence 1)");
            using var server = new Tls13RecordProtection(Aes128Sha256, Rfc8448.ServerApplicationKey, Rfc8448.ServerApplicationIv);
            Check(server.Protect(ContentType.ApplicationData, Rfc8448.ApplicationPayload, 1).SequenceEqual(Rfc8448.ServerApplicationRecord), "Server data record (sequence 1)");
            Check(server.Protect(ContentType.Alert, [1, 0], 2).SequenceEqual(Rfc8448.ServerAlertRecord), "Server close_notify record (sequence 2)");

            var (type, plaintext) = server.Unprotect(Record(Rfc8448.ServerApplicationRecord), 1);
            Check(type == ContentType.ApplicationData && plaintext.SequenceEqual(Rfc8448.ApplicationPayload), "Decryption round trip");
            ExpectAlert(TlsAlertDescription.BadRecordMac, () => server.Unprotect(Record(Rfc8448.ServerApplicationRecord), 2)); // Wrong nonce.
            var tampered = (byte[])Rfc8448.ServerApplicationRecord.Clone();
            tampered[^1] ^= 1;
            ExpectAlert(TlsAlertDescription.BadRecordMac, () => server.Unprotect(Record(tampered), 1));
            var header = (byte[])Rfc8448.ServerApplicationRecord.Clone();
            header[0] = (byte)ContentType.Handshake; // The header is authenticated too, and must say application_data.
            ExpectAlert(TlsAlertDescription.UnexpectedMessage, () => server.Unprotect(Record(header), 1));
        });
        test("RFC 8448 3: hellos, Certificate and CertificateVerify parse and re-encode identically", () =>
        {
            var reader = new RecordReader();
            reader.Append(Rfc8448.ClientHelloRecord);
            Check(reader.TryRead(out var record) && record.Type == ContentType.Handshake && record.Version == (ushort)TlsVersion.Tls10 &&
                  record.Fragment.SequenceEqual(Rfc8448.ClientHello), "ClientHello record framing");
            var hello = ClientHello.Parse(Rfc8448.ClientHello.AsSpan(HandshakeMessage.HeaderLength));
            Check(hello.Serialize().SequenceEqual(Rfc8448.ClientHello), "ClientHello round trip");
            Check(hello.CipherSuites.SequenceEqual([(ushort)0x1301, (ushort)0x1303, (ushort)0x1302]) &&
                  ServerNameExtension.Parse(hello.Extensions.Find(ExtensionType.ServerName)) == "server" &&
                  KeyShareExtension.ParseClient(hello.Extensions.Find(ExtensionType.KeyShare)) is [{ Group: TlsNamedGroup.X25519 } share] &&
                  share.KeyExchange.SequenceEqual(Rfc8448.ClientPublicKey), "ClientHello fields");

            var serverHello = ServerHello.Parse(Rfc8448.ServerHello.AsSpan(HandshakeMessage.HeaderLength));
            var rebuilt = new ServerHello
            {
                Random = serverHello.Random, CipherSuite = (ushort)TlsCipherSuite.TlsAes128GcmSha256,
                Extensions =
                [
                    KeyShareExtension.ForServer(new KeyShareEntry(TlsNamedGroup.X25519, Rfc8448.ServerPublicKey)),
                    SupportedVersionsExtension.ForServer(TlsVersion.Tls13),
                ],
            };
            Check(rebuilt.Serialize().SequenceEqual(Rfc8448.ServerHello) && !serverHello.IsHelloRetryRequest, "ServerHello built from its fields");

            var certificate = CertificateMessage.Parse(Rfc8448.Certificate.AsSpan(HandshakeMessage.HeaderLength), TlsVersion.Tls13);
            Check(certificate.Serialize(TlsVersion.Tls13).SequenceEqual(Rfc8448.Certificate), "Certificate round trip");
            var verify = DigitallySigned.ParseCertificateVerify(Rfc8448.CertificateVerify.AsSpan(HandshakeMessage.HeaderLength));
            Check(verify.Scheme == TlsSignatureScheme.RsaPssRsaeSha256 && verify.SerializeCertificateVerify().SequenceEqual(Rfc8448.CertificateVerify),
                "CertificateVerify round trip");
            var extensions = SimpleMessages.ParseEncryptedExtensions(Rfc8448.EncryptedExtensions.AsSpan(HandshakeMessage.HeaderLength));
            Check(SimpleMessages.EncryptedExtensions(extensions).SequenceEqual(Rfc8448.EncryptedExtensions), "EncryptedExtensions round trip");

            // The recorded RSA-PSS signature verifies with the certificate's key over our computed content.
            var transcript = new TranscriptHash();
            foreach (var message in new[] { Rfc8448.ClientHello, Rfc8448.ServerHello, Rfc8448.EncryptedExtensions, Rfc8448.Certificate })
                transcript.Add(message);
            var content = TlsSignatures.Tls13SignedContent(server: true, transcript.Hash(HashAlgorithmName.SHA256));
            Check(TlsSignatures.Verify(verify.Scheme, TraceCertificate(), content, verify.Signature, TlsVersion.Tls13), "Trace signature does not verify");
            content[^1] ^= 1;
            Check(!TlsSignatures.Verify(verify.Scheme, TraceCertificate(), content, verify.Signature, TlsVersion.Tls13), "Altered transcript verified");
        });
        test("RFC 8448 3: server engine answers the trace ClientHello with the trace's exact records", () =>
        {
            var engine = new TlsEngine(TraceServerOptions());
            engine.Receive(Rfc8448.ClientHelloRecord);
            var output = engine.TakeOutput();
            Check(output.SequenceEqual([.. Rfc8448.ServerHelloRecord, .. Rfc8448.ServerFlightRecord]),
                $"Server flight differs at byte {FirstDifference(output, [.. Rfc8448.ServerHelloRecord, .. Rfc8448.ServerFlightRecord])}");
            var protocol = (Tls13Handshake)engine.Protocol;
            Check(protocol.Schedule.HandshakeSecret!.SequenceEqual(Rfc8448.HandshakeSecret) &&
                  protocol.ClientApplicationSecret!.SequenceEqual(Rfc8448.ClientApplicationTrafficSecret), "Server secrets");
            Check(!engine.HandshakeComplete, "Server completed before the client's Finished");

            engine.Receive(Rfc8448.ClientFinishedRecord);
            Check(engine.HandshakeComplete && engine.FailureReason is null && engine.ServerName == "server" &&
                  engine.Group == TlsNamedGroup.X25519 && engine.SignatureScheme == TlsSignatureScheme.RsaPssRsaeSha256, "Client Finished rejected");
            engine.Receive(Rfc8448.ClientApplicationRecord);
            Check(ReadAll(engine).SequenceEqual(Rfc8448.ApplicationPayload), "Client application data");
            engine.Receive(Rfc8448.ClientAlertRecord);
            Check(engine.PeerClosed && !engine.IsFailed, "Client close_notify");
        });
        test("RFC 8448 3: client engine replays the trace and writes the trace's exact records", () =>
        {
            var engine = new TlsEngine(new TlsClientOptions
            {
                ClientHelloOverride = Rfc8448.ClientHello, TargetHost = "server",
                KeyExchangeFactory = group => group == TlsNamedGroup.X25519
                    ? new FixedKeyExchange(TlsNamedGroup.X25519, Rfc8448.ClientPublicKey, Rfc8448.ServerPublicKey, Rfc8448.SharedSecret) : null,
                CertificateValidation = (leaf, _) => leaf.RawData.SequenceEqual(TraceCertificate().RawData),
            });
            engine.Start();
            Check(engine.TakeOutput().SequenceEqual(Rfc8448.ClientHelloRecord), "ClientHello record");
            engine.Receive([.. Rfc8448.ServerHelloRecord, .. Rfc8448.ServerFlightRecord]);
            var finished = engine.TakeOutput();
            Check(engine.FailureReason is null, $"Client failed: {engine.FailureReason}");
            Check(finished.SequenceEqual(Rfc8448.ClientFinishedRecord), $"Client Finished record differs at byte {FirstDifference(finished, Rfc8448.ClientFinishedRecord)}");
            Check(engine.HandshakeComplete && engine.PeerCertificate is not null, "Handshake incomplete");

            engine.Receive([.. Rfc8448.NewSessionTicketRecord, .. Rfc8448.ServerApplicationRecord]);
            Check(ReadAll(engine).SequenceEqual(Rfc8448.ApplicationPayload), "Server application data after the ticket");
            engine.Send(Rfc8448.ApplicationPayload);
            Check(engine.TakeOutput().SequenceEqual(Rfc8448.ClientApplicationRecord), "Client application record");
            engine.Close();
            Check(engine.TakeOutput().SequenceEqual(Rfc8448.ClientAlertRecord), "Client close_notify record");
            engine.Receive(Rfc8448.ServerAlertRecord);
            Check(engine.PeerClosed && !engine.IsFailed, "Server close_notify");
        });
        test("RFC 8448 5: P-256 ECDHE and the HelloRetryRequest transcript match byte for byte", () =>
        {
            using var server = new EcdheKeyExchange(TlsNamedGroup.Secp256r1, Rfc8448.RetryServerPrivateKey, Rfc8448.RetryServerPublicKey);
            using var client = new EcdheKeyExchange(TlsNamedGroup.Secp256r1, Rfc8448.RetryClientPrivateKey, Rfc8448.RetryClientPublicKey);
            Check(server.PublicKey.SequenceEqual(Rfc8448.RetryServerPublicKey) && client.PublicKey.SequenceEqual(Rfc8448.RetryClientPublicKey), "Point encoding");
            Check(server.DeriveSharedSecret(Rfc8448.RetryClientPublicKey).SequenceEqual(Rfc8448.RetrySharedSecret) &&
                  client.DeriveSharedSecret(Rfc8448.RetryServerPublicKey).SequenceEqual(Rfc8448.RetrySharedSecret), "ECDHE shared secret");
            var offCurve = (byte[])Rfc8448.RetryClientPublicKey.Clone();
            offCurve[^1] ^= 1;
            ExpectAlert(TlsAlertDescription.IllegalParameter, () => server.DeriveSharedSecret(offCurve));

            var retry = ServerHello.Parse(Rfc8448.HelloRetryRequest.AsSpan(HandshakeMessage.HeaderLength));
            Check(retry.IsHelloRetryRequest && KeyShareExtension.ParseRetry(retry.Extensions.Find(ExtensionType.KeyShare)) == TlsNamedGroup.Secp256r1,
                "HelloRetryRequest fields");
            var transcript = new TranscriptHash();
            transcript.Add(Rfc8448.RetryClientHello1);
            transcript.ReplaceWithMessageHash(HashAlgorithmName.SHA256);
            transcript.Add(Rfc8448.HelloRetryRequest);
            transcript.Add(Rfc8448.RetryClientHello2);
            transcript.Add(Rfc8448.RetryServerHello);
            var hash = transcript.Hash(HashAlgorithmName.SHA256);
            Check(hash.SequenceEqual(Rfc8448.RetryHelloHash), "Transcript with message_hash");
            var schedule = new Tls13KeySchedule(HashAlgorithmName.SHA256);
            schedule.DeriveHandshakeSecret(Rfc8448.RetrySharedSecret);
            Check(schedule.HandshakeSecret!.SequenceEqual(Rfc8448.RetryHandshakeSecret) &&
                  schedule.ClientHandshakeTrafficSecret(hash).SequenceEqual(Rfc8448.RetryClientHandshakeTrafficSecret) &&
                  schedule.ServerHandshakeTrafficSecret(hash).SequenceEqual(Rfc8448.RetryServerHandshakeTrafficSecret), "Handshake secrets after retry");
        });
        test("RFC 8448 5: client engine answers the HelloRetryRequest with a P-256 share and echoes the cookie", () =>
        {
            var firstShare = KeyShareExtension.ParseClient(ClientHello.Parse(Rfc8448.RetryClientHello1.AsSpan(HandshakeMessage.HeaderLength))
                .Extensions.Find(ExtensionType.KeyShare))[0];
            var engine = new TlsEngine(new TlsClientOptions
            {
                ClientHelloOverride = Rfc8448.RetryClientHello1,
                KeyExchangeFactory = group => group switch
                {
                    TlsNamedGroup.X25519 => new FixedKeyExchange(group, firstShare.KeyExchange, [], []),
                    TlsNamedGroup.Secp256r1 => new EcdheKeyExchange(group, Rfc8448.RetryClientPrivateKey, Rfc8448.RetryClientPublicKey),
                    _ => null,
                },
            });
            engine.Start();
            engine.TakeOutput();
            engine.Receive(Frame(Rfc8448.HelloRetryRequest));
            var reader = new RecordReader();
            reader.Append(engine.TakeOutput());
            var hasRecord = reader.TryRead(out var record);
            Check(!engine.IsFailed && hasRecord, $"No second ClientHello: {engine.FailureReason}");
            var second = ClientHello.Parse(record.Fragment.AsSpan(HandshakeMessage.HeaderLength));
            var expected = ClientHello.Parse(Rfc8448.RetryClientHello2.AsSpan(HandshakeMessage.HeaderLength));
            var retry = ServerHello.Parse(Rfc8448.HelloRetryRequest.AsSpan(HandshakeMessage.HeaderLength));
            Check(KeyShareExtension.ParseClient(second.Extensions.Find(ExtensionType.KeyShare)) is [{ Group: TlsNamedGroup.Secp256r1 } share] &&
                  share.KeyExchange.SequenceEqual(Rfc8448.RetryClientPublicKey), "Second key share");
            Check(second.Extensions.Find(ExtensionType.Cookie).AsSpan().SequenceEqual(retry.Extensions.Find(ExtensionType.Cookie)) &&
                  second.Extensions.Find(ExtensionType.Cookie).AsSpan().SequenceEqual(expected.Extensions.Find(ExtensionType.Cookie)), "Cookie not echoed");
            Check(second.Random.SequenceEqual(expected.Random) && second.CipherSuites.SequenceEqual(expected.CipherSuites), "Second ClientHello changed more than allowed");
            Check(engine.HelloRetryRequested, "Retry not recorded");
        });
        test("RFC 8448 5: server engine asks the x25519-only ClientHello for P-256 and accepts the retry", () =>
        {
            var engine = new TlsEngine(TraceServerOptions() with { Groups = [TlsNamedGroup.Secp256r1], KeyExchangeFactory = TlsKeyExchange.Create });
            engine.Receive(Frame(Rfc8448.RetryClientHello1));
            var retry = ParseHandshakeRecord(engine.TakeOutput());
            Check(retry.IsHelloRetryRequest && retry.CipherSuite == (ushort)TlsCipherSuite.TlsAes128GcmSha256 &&
                  KeyShareExtension.ParseRetry(retry.Extensions.Find(ExtensionType.KeyShare)) == TlsNamedGroup.Secp256r1 &&
                  SupportedVersionsExtension.ParseServer(retry.Extensions.Find(ExtensionType.SupportedVersions)) == 0x0304, "HelloRetryRequest");
            engine.Receive(Frame(Rfc8448.RetryClientHello2));
            var output = engine.TakeOutput();
            var serverHello = ParseHandshakeRecord(output);
            Check(!engine.IsFailed && !serverHello.IsHelloRetryRequest && engine.HelloRetryRequested &&
                  KeyShareExtension.ParseServer(serverHello.Extensions.Find(ExtensionType.KeyShare)).Group == TlsNamedGroup.Secp256r1,
                $"Retry not accepted: {engine.FailureReason}");
            engine.Receive(Frame(Rfc8448.RetryClientHello2));
            Check(engine.AlertSent == TlsAlertDescription.UnexpectedMessage, "A third ClientHello was accepted");
        });
    }

    /// <summary>Server options that reproduce the RFC 8448 server: its random, x25519 key, certificate, signature and EncryptedExtensions.</summary>
    private static TlsServerOptions TraceServerOptions()
    {
        var verify = DigitallySigned.ParseCertificateVerify(Rfc8448.CertificateVerify.AsSpan(HandshakeMessage.HeaderLength));
        var traceExtensions = SimpleMessages.ParseEncryptedExtensions(Rfc8448.EncryptedExtensions.AsSpan(HandshakeMessage.HeaderLength));
        return new TlsServerOptions
        {
            Certificate = TraceCertificate(), CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256], Groups = [TlsNamedGroup.X25519],
            FillRandom = random => ServerHello.Parse(Rfc8448.ServerHello.AsSpan(HandshakeMessage.HeaderLength)).Random.CopyTo(random),
            KeyExchangeFactory = group => group == TlsNamedGroup.X25519
                ? new FixedKeyExchange(TlsNamedGroup.X25519, Rfc8448.ServerPublicKey, Rfc8448.ClientPublicKey, Rfc8448.SharedSecret) : null,
            Signer = new FixedSigner(verify.Signature),
            // The trace server also lists its groups in EncryptedExtensions (allowed by RFC 8446 4.2.7); ours does not.
            AdditionalEncryptedExtensions = [.. traceExtensions.Where(e => e.Type == ExtensionType.SupportedGroups)],
        };
    }

    /// <summary>The trace's RSA certificate (self-signed, CN=rsa, 1024-bit key).</summary>
    private static X509Certificate2 TraceCertificate() => X509CertificateLoader.LoadCertificate(
        CertificateMessage.Parse(Rfc8448.Certificate.AsSpan(HandshakeMessage.HeaderLength), TlsVersion.Tls13).Certificates[0]);

    private static void CheckKeys((byte[] Key, byte[] Iv) keys, byte[] key, byte[] iv, string label) =>
        Check(keys.Key.SequenceEqual(key) && keys.Iv.SequenceEqual(iv), $"{label} key/IV");

    private static TlsRecord Record(byte[] bytes) => new(bytes[..TlsRecord.HeaderLength], bytes[TlsRecord.HeaderLength..]);

    /// <summary>Wraps a handshake message in a plaintext record.</summary>
    private static byte[] Frame(byte[] message) =>
        [.. TlsRecord.CreateHeader(ContentType.Handshake, (ushort)TlsVersion.Tls12, message.Length), .. message];

    /// <summary>The ServerHello that opens a plaintext handshake record (possibly followed by more of the flight).</summary>
    private static ServerHello ParseHandshakeRecord(byte[] records)
    {
        var reader = new RecordReader();
        reader.Append(records);
        Check(reader.TryRead(out var record) && record.Type == ContentType.Handshake, "No handshake record");
        var messages = new HandshakeReader();
        messages.Append(record.Fragment);
        Check(messages.TryRead(out var message) && message.Type == HandshakeType.ServerHello, "Record does not start with ServerHello");
        return ServerHello.Parse(message.Body);
    }

    private static int FirstDifference(byte[] actual, byte[] expected)
    {
        var length = Math.Min(actual.Length, expected.Length);
        for (var i = 0; i < length; i++) if (actual[i] != expected[i]) return i;
        return length;
    }

    /// <summary>A key exchange with recorded values: our public key, the peer's expected key, and the shared secret.</summary>
    private sealed class FixedKeyExchange(TlsNamedGroup group, byte[] publicKey, byte[] expectedPeer, byte[] sharedSecret) : TlsKeyExchange
    {
        public override TlsNamedGroup Group => group;
        public override byte[] PublicKey => publicKey;
        public override byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey)
        {
            Check(peerPublicKey.SequenceEqual(expectedPeer), "Key exchange received an unexpected peer key");
            return sharedSecret;
        }
    }

    /// <summary>Returns a recorded RSA-PSS signature, since real ones are randomized.</summary>
    private sealed class FixedSigner(byte[] signature) : TlsSigner
    {
        public override ServerAuthentication KeyType => ServerAuthentication.Rsa;
        public override IReadOnlyList<TlsSignatureScheme> Schemes(TlsVersion version) => [TlsSignatureScheme.RsaPssRsaeSha256];
        public override byte[] Sign(TlsSignatureScheme scheme, byte[] data) => signature;
    }
}
