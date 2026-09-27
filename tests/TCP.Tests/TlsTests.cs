using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp.Segments;
using TCP.L5_7.Application.Tls;
using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Cryptography;
using TCP.L5_7.Application.Tls.Demos;
using TCP.L5_7.Application.Tls.Extensions;
using TCP.L5_7.Application.Tls.Handshake;
using TCP.L5_7.Application.Tls.Handshake.Messages;
using TCP.L5_7.Application.Tls.Records;
using TCP.L5_7.Application.Tls.Wire;

namespace TCP.Tests;

/// <summary>
/// TLS regression tests: RFC 8448 byte-for-byte traces, our client against our server over the in-memory TCP
/// network, and interoperability with .NET's <see cref="System.Net.Security.SslStream"/>.
/// </summary>
internal static partial class TlsTests
{
    private const ushort HttpsPort = 443;
    private static readonly Lazy<X509Certificate2> EcdsaCertificate = new(() => TlsCertificates.CreateSelfSigned("tls.test"));
    private static readonly Lazy<X509Certificate2> RsaCertificate = new(CreateRsaCertificate);

    public static int Run()
    {
        var passed = 0;
        RunRfc8448Tests(Test);
        RunPrimitiveTests(Test);
        RunConnectionTests(Test);
        passed += RunInteropTests();
        return passed;
        void Test(string name, Action body) { body(); passed++; Console.WriteLine($"PASS: TLS {name}"); }
    }

    private static void RunPrimitiveTests(Action<string, Action> test)
    {
        test("TLS 1.2 PRF matches the published P_SHA256 vector and an OpenSSL P_SHA384 vector", () =>
        {
            // P_SHA256 vector widely used since the TLS 1.2 drafts; both regenerated with `openssl kdf TLS1-PRF`.
            var sha256 = Tls12Prf.Compute(HashAlgorithmName.SHA256, Convert.FromHexString("9BBE436BA940F017B17652849A71DB35"), "test label",
                Convert.FromHexString("A0BA9F936CDA311827A6F796FFD5198C"), 100);
            Check(sha256.SequenceEqual(Convert.FromHexString(
                "E3F229BA727BE17B8D122620557CD453C2AAB21D07C3D495329B52D4E61EDB5A6B301791E90D35C9C9A46B4E14BAF9AF0FA022F7077DEF17ABFD3797C0564BAB" +
                "4FBC91666E9DEF9B97FCE34F796789BAA48082D122EE42C5A72E5A5110FFF70187347B66")), "P_SHA256");
            var sha384 = Tls12Prf.Compute(HashAlgorithmName.SHA384, Convert.FromHexString("B80B733D6CEEFCDC71566EA48E5567DF"), "test label",
                Convert.FromHexString("CD665CF6A8447DD6FF8B27555EDB7465"), 48);
            Check(sha384.SequenceEqual(Convert.FromHexString(
                "7B0C18E9CED410ED1804F2CFA34A336A1C14DFFB4900BB5FD7942107E81C83CDE9CA0FAA60BE9FE34F82B1233C9146A0")), "P_SHA384");
        });
        test("finite-field Diffie-Hellman: the textbook example and RFC 7919 ffdhe2048", () =>
        {
            var alice = new FiniteFieldDiffieHellman.Party(FiniteFieldDiffieHellman.Toy, privateKey: 6);
            var bob = new FiniteFieldDiffieHellman.Party(FiniteFieldDiffieHellman.Toy, privateKey: 15);
            Check(alice.PublicKey == 8 && bob.PublicKey == 19, "Toy public values");
            Check(alice.ComputeSharedSecret(bob.PublicKey) == 2 && bob.ComputeSharedSecret(alice.PublicKey) == 2, "Toy shared secret");
            var group = FiniteFieldDiffieHellman.Ffdhe2048;
            Check(group.Prime.GetBitLength() == 2048 && IsProbablePrime(group.Prime) && IsProbablePrime((group.Prime - 1) / 2),
                "ffdhe2048 is not a 2048-bit safe prime (transcription error?)");
            var a = new FiniteFieldDiffieHellman.Party(group);
            var b = new FiniteFieldDiffieHellman.Party(group);
            Check(a.ComputeSharedSecret(b.PublicKey) == b.ComputeSharedSecret(a.PublicKey) && a.PublicKey != b.PublicKey, "ffdhe2048 agreement");
            ThrowsArgument(() => a.ComputeSharedSecret(group.Prime - 1)); // Order-2 element: the "secret" would be ±1.
        });
        test("wire codec: vectors, truncation and overlong prefixes", () =>
        {
            var writer = new TlsWriter();
            using (writer.OpenVector(2)) { writer.WriteUInt16(0x0304); writer.WriteUInt24(0x010203); }
            Check(writer.ToArray().SequenceEqual(new byte[] { 0, 5, 3, 4, 1, 2, 3 }), "Vector encoding");
            var reader = new TlsReader(writer.WrittenSpan);
            var inner = new TlsReader(reader.ReadVector16());
            Check(inner.ReadUInt16() == 0x0304 && inner.ReadUInt24() == 0x010203 && inner.IsEmpty && reader.IsEmpty, "Vector decoding");
            ExpectAlert(TlsAlertDescription.DecodeError, () => new TlsReader([0, 9, 1]).ReadVector16());
            ExpectAlert(TlsAlertDescription.DecodeError, () => new TlsReader([1, 2]).EnsureEnd());
            var overlong = new TlsWriter();
            try { using (overlong.OpenVector(1)) overlong.WriteBytes(new byte[256]); throw new Exception("Overlong vector accepted"); }
            catch (InvalidOperationException) { }
            ExpectAlert(TlsAlertDescription.IllegalParameter, () => ClientHello.Parse(ClientHelloWithDuplicateExtension()));
        });
        test("record reader: fragmented arrival, coalesced records and hostile headers", () =>
        {
            byte[] two = [.. TlsRecord.CreateHeader(ContentType.Handshake, 0x0303, 3), 1, 2, 3, .. TlsRecord.CreateHeader(ContentType.Alert, 0x0303, 2), 1, 0];
            var reader = new RecordReader();
            foreach (var b in two[..6]) reader.Append([b]);
            Check(!reader.TryRead(out _) && reader.HasPartialRecord, "Partial record returned");
            reader.Append(two[6..]);
            Check(reader.TryRead(out var first) && first.Fragment.SequenceEqual(new byte[] { 1, 2, 3 }) &&
                  reader.TryRead(out var second) && second.Type == ContentType.Alert && !reader.TryRead(out _), "Coalesced records");
            ExpectAlert(TlsAlertDescription.UnexpectedMessage, () => { var r = new RecordReader(); r.Append("GET / HTTP/1.1\r\n"u8); r.TryRead(out _); });
            ExpectAlert(TlsAlertDescription.RecordOverflow, () => { var r = new RecordReader(); r.Append([23, 3, 3, 0xFF, 0xFF]); r.TryRead(out _); });
        });
    }

    private static void RunConnectionTests(Action<string, Action> test)
    {
        test("TLS 1.3 over TCP: ECDHE P-256, ECDSA, AES-128-GCM, ALPN h2, data both ways, close_notify", () =>
        {
            var pair = TlsPair.Connect(ClientOptions() with { ApplicationProtocols = ["h2", "http/1.1"] },
                ServerOptions() with { ApplicationProtocols = ["h2"] });
            foreach (var side in new[] { pair.Client, pair.Server })
                Check(side.State == TlsConnectionState.Established && side.Version == TlsVersion.Tls13 &&
                      side.CipherSuite == TlsCipherSuite.TlsAes128GcmSha256 && side.KeyExchangeGroup == TlsNamedGroup.Secp256r1 &&
                      side.SignatureScheme == TlsSignatureScheme.EcdsaSecp256r1Sha256 && side.ApplicationProtocol == "h2" &&
                      !side.HelloRetryRequested, $"Negotiation ({(side.IsServer ? "server" : "client")})");
            Check(pair.Server.ServerName == "tls.test" && pair.Client.RemoteCertificate!.Thumbprint == EcdsaCertificate.Value.Thumbprint, "SNI or certificate");
            pair.Exchange("GET / HTTP/1.1\r\n\r\n"u8.ToArray(), "HTTP/1.1 200 OK\r\n\r\n"u8.ToArray());
            pair.Client.Close();
            pair.Settle(() => pair.Server.PeerClosed);
            Check(pair.Server.State == TlsConnectionState.Established && pair.Server.Send("late"u8) == 4, "TLS 1.3 half-close stopped the server");
            pair.Settle(() => pair.Client.Available == 4);
            pair.Server.Close();
            pair.Settle(() => pair.Client.PeerClosed && pair.Server.State == TlsConnectionState.Closed && pair.Client.State == TlsConnectionState.Closed);
            Check(pair.Client.FailureReason is null && pair.Server.FailureReason is null, "Clean close reported a failure");
        });
        foreach (var suite in new[] { TlsCipherSuite.TlsAes256GcmSha384, TlsCipherSuite.TlsChaCha20Poly1305Sha256 })
            test($"TLS 1.3 over TCP with {suite}", () =>
            {
                var pair = TlsPair.Connect(ClientOptions(), ServerOptions() with { CipherSuites = [suite] });
                Check(pair.Client.CipherSuite == suite, "Suite not negotiated");
                pair.Exchange(RandomBytes(5000), RandomBytes(7000));
            });
        foreach (var (suite, rsa) in new[] { (TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256, false), (TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384, false),
                     (TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256, true), (TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384, true) })
            test($"TLS 1.2 over TCP with {suite} and the extended master secret", () =>
            {
                var server = ServerOptions(rsa) with { CipherSuites = [suite], ApplicationProtocols = ["h2"] };
                var pair = TlsPair.Connect(ClientOptions(rsa) with { MaximumVersion = TlsVersion.Tls12, ApplicationProtocols = ["h2"] }, server);
                foreach (var side in new[] { pair.Client, pair.Server })
                    Check(side.Version == TlsVersion.Tls12 && side.CipherSuite == suite && side.ExtendedMasterSecret && side.ApplicationProtocol == "h2",
                        $"Negotiation ({(side.IsServer ? "server" : "client")})");
                pair.Exchange(RandomBytes(20000), RandomBytes(3000));
                pair.Client.Close(); // TLS 1.2: the server answers close_notify with its own and both close.
                pair.Settle(() => pair.Client.State == TlsConnectionState.Closed && pair.Server.State == TlsConnectionState.Closed);
                Check(pair.Client.FailureReason is null && pair.Server.FailureReason is null, "TLS 1.2 closure failed");
            });
        test("TLS 1.3 with an RSA certificate signs with RSA-PSS", () =>
        {
            var pair = TlsPair.Connect(ClientOptions(rsa: true), ServerOptions(rsa: true));
            Check(pair.Client.SignatureScheme == TlsSignatureScheme.RsaPssRsaeSha256, "RSA-PSS not used");
            pair.Exchange([1, 2, 3], [4, 5, 6]);
        });
        test("version negotiation: TLS 1.2-only client, TLS 1.2-only server, and no overlap", () =>
        {
            Check(TlsPair.Connect(ClientOptions() with { MaximumVersion = TlsVersion.Tls12 }, ServerOptions()).Server.Version == TlsVersion.Tls12, "1.2 client");
            Check(TlsPair.Connect(ClientOptions(), ServerOptions() with { MaximumVersion = TlsVersion.Tls12 }).Client.Version == TlsVersion.Tls12, "1.2 server");
            var pair = TlsPair.Connect(ClientOptions() with { MinimumVersion = TlsVersion.Tls13 }, ServerOptions() with { MaximumVersion = TlsVersion.Tls12 }, expectSuccess: false);
            Check(pair.Server.AlertSent == TlsAlertDescription.ProtocolVersion && pair.Client.AlertReceived == TlsAlertDescription.ProtocolVersion &&
                  pair.Client.State == TlsConnectionState.Closed, "Version mismatch not refused");
        });
        test("HelloRetryRequest when the client's key share is for a group the server does not use", () =>
        {
            var pair = TlsPair.Connect(ClientOptions() with { Groups = [TlsNamedGroup.Secp384r1, TlsNamedGroup.Secp256r1] },
                ServerOptions() with { Groups = [TlsNamedGroup.Secp256r1] });
            Check(pair.Client.HelloRetryRequested && pair.Server.HelloRetryRequested && pair.Client.KeyExchangeGroup == TlsNamedGroup.Secp256r1, "No retry");
            pair.Exchange([9], [8]);
            var refused = TlsPair.Connect(ClientOptions() with { Groups = [TlsNamedGroup.Secp384r1] },
                ServerOptions() with { Groups = [TlsNamedGroup.Secp256r1] }, expectSuccess: false);
            Check(refused.Server.AlertSent == TlsAlertDescription.HandshakeFailure, "No common group accepted");
        });
        test("TLS 1.3 client detects a downgrade to TLS 1.2 by the server random's DOWNGRD marker", () =>
        {
            var server = new TlsEngine(ServerOptions());
            var legacyClient = new TlsEngine(ClientOptions() with { MaximumVersion = TlsVersion.Tls12 });
            legacyClient.Start();
            server.Receive(legacyClient.TakeOutput()); // As if an attacker stripped supported_versions from a TLS 1.3 offer.
            var flight = server.TakeOutput();
            var serverHello = ParseHandshakeRecord(flight);
            Check(serverHello.Random.AsSpan(24).SequenceEqual(ServerHello.Tls12DowngradeSentinel), "Server did not mark the downgrade");
            var modernClient = new TlsEngine(ClientOptions());
            modernClient.Start();
            modernClient.TakeOutput();
            modernClient.Receive(flight);
            Check(modernClient.AlertSent == TlsAlertDescription.IllegalParameter && modernClient.FailureReason == "Server random carries a downgrade marker: TLS 1.3 was removed in transit.",
                $"Downgrade accepted: {modernClient.FailureReason}");
        });
        test("ALPN without a common protocol fails with no_application_protocol", () =>
        {
            var pair = TlsPair.Connect(ClientOptions() with { ApplicationProtocols = ["http/1.1"] }, ServerOptions() with { ApplicationProtocols = ["h2"] }, expectSuccess: false);
            Check(pair.Server.AlertSent == TlsAlertDescription.NoApplicationProtocol && pair.Client.AlertReceived == TlsAlertDescription.NoApplicationProtocol, "ALPN mismatch");
            var optional = TlsPair.Connect(ClientOptions(), ServerOptions() with { ApplicationProtocols = ["h2"] });
            Check(optional.Client.ApplicationProtocol is null, "ALPN chosen without an offer");
        });
        test("an untrusted certificate is refused with bad_certificate, encrypted under the handshake keys", () =>
        {
            foreach (var version in new[] { TlsVersion.Tls13, TlsVersion.Tls12 })
            {
                var pair = TlsPair.Connect(ClientOptions() with { MaximumVersion = version, CertificateValidation = null }, ServerOptions(), expectSuccess: false);
                Check(pair.Client.AlertSent == TlsAlertDescription.BadCertificate && pair.Server.AlertReceived == TlsAlertDescription.BadCertificate &&
                      pair.Server.State == TlsConnectionState.Closed, $"Self-signed certificate accepted by default ({version})");
            }
        });
        test("a tampered record fails with bad_record_mac and ends both sides", () =>
        {
            var pair = TlsPair.Connect(ClientOptions(), ServerOptions());
            pair.Network.Filter = (fromA, packet) => fromA && packet.Payload.Length > 60 ? CorruptLastByte(packet) : packet;
            pair.Client.Send(RandomBytes(100));
            pair.Settle(() => pair.Server.State == TlsConnectionState.Closed && pair.Client.State == TlsConnectionState.Closed);
            Check(pair.Server.AlertSent == TlsAlertDescription.BadRecordMac && pair.Client.AlertReceived == TlsAlertDescription.BadRecordMac, "Tampering undetected");
        });
        test("a megabyte each way spans many records and survives a small MTU and backpressure", () =>
        {
            var pair = TlsPair.Connect(ClientOptions(), ServerOptions(), mtu: 600);
            var up = RandomBytes(1_000_000);
            var down = RandomBytes(1_000_000);
            pair.Exchange(up, down, chunked: true);
        });
        test("TLS 1.3 KeyUpdate: both directions rotate keys and data keeps flowing", () =>
        {
            var pair = TlsPair.Connect(ClientOptions(), ServerOptions());
            pair.Client.RequestKeyUpdate();
            pair.Settle(() => pair.Server.KeyUpdatesReceived == 1 && pair.Client.KeyUpdatesReceived == 1);
            pair.Exchange(RandomBytes(3000), RandomBytes(3000));
            pair.Server.RequestKeyUpdate();
            pair.Settle(() => pair.Client.KeyUpdatesReceived == 2 && pair.Server.KeyUpdatesReceived == 2);
            pair.Exchange([1], [2]);
        });
        test("TCP FIN without close_notify is reported as truncation", () =>
        {
            var pair = TlsPair.Connect(ClientOptions(), ServerOptions());
            pair.Client.Transport.Close();
            pair.Settle(() => pair.Server.State == TlsConnectionState.Closed);
            Check(pair.Server.FailureReason == "Peer closed the TCP connection without close_notify; data may have been truncated.", "Truncation not reported");
        });
        test("sending before the handshake completes is refused; close_notify mid-handshake cancels it", () =>
        {
            var n = new TcpTests.Network();
            n.TcpB.Listen(HttpsPort, tcp => TlsConnection.AuthenticateAsServer(tcp, ServerOptions()));
            var client = TlsConnection.AuthenticateAsClient(n.TcpA.Connect(n.B.LocalAddress, HttpsPort), ClientOptions());
            try { client.Send([1]); throw new Exception("Send before handshake accepted"); }
            catch (InvalidOperationException) { }
            // A client that gives up mid-handshake with close_notify leaves the server failed, not half-open.
            var engine = new TlsEngine(ServerOptions());
            var clientEngine = new TlsEngine(ClientOptions() with { MaximumVersion = TlsVersion.Tls12 });
            clientEngine.Start();
            engine.Receive(clientEngine.TakeOutput());
            engine.Receive([.. TlsRecord.CreateHeader(ContentType.Alert, (ushort)TlsVersion.Tls12, 2), 1, 0]);
            Check(engine.IsFailed && engine.PeerClosed && engine.AlertSent is null && !engine.CloseNotifySent, "Handshake close_notify not treated as cancellation");
        });
    }

    private static TlsServerOptions ServerOptions(bool rsa = false) =>
        new() { Certificate = rsa ? RsaCertificate.Value : EcdsaCertificate.Value };

    private static TlsClientOptions ClientOptions(bool rsa = false)
    {
        var thumbprint = (rsa ? RsaCertificate.Value : EcdsaCertificate.Value).Thumbprint;
        return new() { TargetHost = "tls.test", CertificateValidation = (leaf, _) => leaf.Thumbprint == thumbprint };
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=tls.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    /// <summary>Flips the last byte of a TCP segment's data and re-checksums it, so the damage reaches TLS instead of TCP.</summary>
    private static IPv4Packet CorruptLastByte(IPv4Packet packet)
    {
        var segment = TcpSegment.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span);
        if (segment.Payload.IsEmpty) return packet;
        var data = segment.Payload.ToArray();
        data[^1] ^= 1;
        return packet with { Payload = (segment with { Payload = data }).Serialize(packet.SourceAddress, packet.DestinationAddress) };
    }

    private static byte[] ReadAll(TlsEngine engine)
    {
        var bytes = new byte[engine.Available];
        engine.Read(bytes);
        return bytes;
    }

    /// <summary>A ClientHello body carrying extended_master_secret twice, which RFC 8446 4.2 forbids.</summary>
    private static byte[] ClientHelloWithDuplicateExtension()
    {
        var hello = new ClientHello
        {
            Random = new byte[ClientHello.RandomLength], CipherSuites = [(ushort)TlsCipherSuite.TlsAes128GcmSha256],
            Extensions = [SimpleExtensions.ExtendedMasterSecret, SimpleExtensions.ExtendedMasterSecret],
        };
        return hello.Serialize()[HandshakeMessage.HeaderLength..];
    }

    /// <summary>Miller-Rabin with fixed small-prime bases: enough to catch a mistyped constant.</summary>
    private static bool IsProbablePrime(BigInteger n)
    {
        var d = n - 1;
        var r = 0;
        while (d.IsEven) { d >>= 1; r++; }
        foreach (int a in new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 })
        {
            var x = BigInteger.ModPow(a, d, n);
            if (x.IsOne || x == n - 1) continue;
            var witness = true;
            for (var i = 1; i < r && witness; i++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1) witness = false;
            }
            if (witness) return false;
        }
        return true;
    }

    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }

    private static void ThrowsArgument(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new Exception("Expected an argument exception");
    }

    private static void ExpectAlert(TlsAlertDescription alert, Action action)
    {
        try { action(); }
        catch (TlsAlertException error) when (error.Description == alert) { return; }
        throw new Exception($"Expected alert {alert}");
    }

    /// <summary>A TLS client and server over the two-host in-memory TCP network.</summary>
    private sealed class TlsPair
    {
        private TlsPair(TcpTests.Network network, TlsConnection client, TlsConnection server)
        {
            Network = network;
            Client = client;
            Server = server;
        }

        public TcpTests.Network Network { get; }
        public TlsConnection Client { get; }
        public TlsConnection Server { get; }

        /// <summary>Connects TCP, starts TLS on both ends, and runs the network until the handshake settles.</summary>
        public static TlsPair Connect(TlsClientOptions client, TlsServerOptions server, int mtu = 1500, bool expectSuccess = true)
        {
            var network = new TcpTests.Network(mtu);
            TlsConnection? accepted = null;
            network.TcpB.Listen(HttpsPort, tcp => accepted = TlsConnection.AuthenticateAsServer(tcp, server));
            var connection = TlsConnection.AuthenticateAsClient(network.TcpA.Connect(network.B.LocalAddress, HttpsPort), client);
            network.Pump();
            var pair = new TlsPair(network, connection, accepted!);
            pair.Settle(() => (connection.State != TlsConnectionState.Handshaking && accepted?.State != TlsConnectionState.Handshaking) ||
                              connection.State == TlsConnectionState.Closed);
            if (expectSuccess)
                Check(connection.State == TlsConnectionState.Established && accepted!.State == TlsConnectionState.Established,
                    $"Handshake failed: client {connection.FailureReason}, server {accepted?.FailureReason}");
            else
                pair.Settle(() => connection.State == TlsConnectionState.Closed && accepted!.State == TlsConnectionState.Closed);
            return pair;
        }

        /// <summary>Pumps packets and advances the clock (for delayed ACKs) until <paramref name="done"/> holds.</summary>
        public void Settle(Func<bool> done)
        {
            for (var step = 0; step < 5000; step++)
            {
                Network.Pump();
                if (done()) return;
                Network.AdvanceMilliseconds(50);
            }
            throw new Exception($"TLS exchange did not settle: client {Client.State} {Client.FailureReason}, server {Server?.State} {Server?.FailureReason}");
        }

        /// <summary>Sends <paramref name="up"/> client-to-server and <paramref name="down"/> back, honoring partial Sends.</summary>
        public void Exchange(byte[] up, byte[] down, bool chunked = false)
        {
            var atServer = new List<byte>();
            var atClient = new List<byte>();
            int sentUp = 0, sentDown = 0;
            Settle(() =>
            {
                if (sentUp < up.Length) sentUp += Client.Send(up.AsSpan(sentUp, chunked ? Math.Min(65536, up.Length - sentUp) : up.Length - sentUp));
                if (sentDown < down.Length) sentDown += Server.Send(down.AsSpan(sentDown, chunked ? Math.Min(65536, down.Length - sentDown) : down.Length - sentDown));
                atServer.AddRange(Drain(Server));
                atClient.AddRange(Drain(Client));
                return atServer.Count >= up.Length && atClient.Count >= down.Length;
            });
            Check(atServer.SequenceEqual(up) && atClient.SequenceEqual(down), "Application data corrupted");
        }

        private static byte[] Drain(TlsConnection connection)
        {
            var bytes = new byte[connection.Available];
            connection.Read(bytes);
            return bytes;
        }
    }
}
