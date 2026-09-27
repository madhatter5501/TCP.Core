using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L5_7.Application.Tls;
using TlsCipherSuite = TCP.L5_7.Application.Tls.Cryptography.TlsCipherSuite;

namespace TCP.Tests;

/// <summary>
/// Interoperability with .NET's SslStream, which uses the platform's TLS (SecureTransport or Network.framework on
/// macOS, SChannel on Windows, OpenSSL on Linux), running over the in-memory stack through <see cref="TcpConnectionStream"/>.
/// </summary>
/// <remarks>
/// The test thread plays the stack's protocol thread: it pumps packets and services the stream adapter, while
/// SslStream runs asynchronously on the thread pool. On macOS the SecureTransport provider has no TLS 1.3, so the
/// TLS 1.3 client uses the Network.framework provider (opted into below), and the TLS 1.3 SslStream server case,
/// which neither provider can serve, is skipped.
/// </remarks>
internal static partial class TlsTests
{
    private static readonly TimeSpan InteropTimeout = TimeSpan.FromSeconds(30);
    private static readonly byte[] Ping = "ping over TLS"u8.ToArray();

    private static int RunInteropTests()
    {
        // Must precede the first SslStream. Only affects macOS, where it is the sole TLS 1.3 client provider.
        AppContext.SetSwitch("System.Net.Security.UseNetworkFramework", true);
        var passed = 0;
        foreach (var protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
            Run($"SslStream {Describe(protocol)} client talks to our server (ALPN h2, echo, close_notify)", () => SslStreamClientToOurServer(protocol));
        foreach (var protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            if (protocol == SslProtocols.Tls13 && OperatingSystem.IsMacOS())
            {
                Console.WriteLine("SKIP: TLS our client talks to an SslStream TLS 1.3 server (macOS SslStream cannot serve TLS 1.3)");
                continue;
            }
            Run($"our client talks to an SslStream {Describe(protocol)} server (ALPN h2, echo)", () => OurClientToSslStreamServer(protocol));
        }
        // An independent TLS 1.3 server for our client where SslStream cannot provide one; optional, as it needs OpenSSL 3.
        if (FindOpenSsl() is { } openssl)
            foreach (var version in new[] { TlsVersion.Tls13, TlsVersion.Tls12 })
                Run($"our client talks to OpenSSL s_server over a loopback socket bridge ({version})", () => OurClientToOpenSslServer(openssl, version));
        else
            Console.WriteLine("SKIP: TLS our client talks to OpenSSL s_server (OpenSSL 3 not found)");
        return passed;

        void Run(string name, Action body) { body(); passed++; Console.WriteLine($"PASS: TLS {name}"); }
    }

    private static string Describe(SslProtocols protocol) => protocol == SslProtocols.Tls13 ? "TLS 1.3" : "TLS 1.2";

    /// <summary>SslStream as the client, our <see cref="TlsConnection"/> as an echo server.</summary>
    private static void SslStreamClientToOurServer(SslProtocols protocol)
    {
        var network = new TcpTests.Network();
        using var activity = new SemaphoreSlim(0);
        TlsConnection? server = null;
        network.TcpB.Listen(HttpsPort, tcp =>
        {
            server = TlsConnection.AuthenticateAsServer(tcp, ServerOptions() with { ApplicationProtocols = ["h2", "http/1.1"] });
            server.DataAvailable += connection =>
            {
                var bytes = new byte[connection.Available];
                connection.Read(bytes);
                connection.Send([.. bytes.Reverse()]);
            };
        });
        var stream = new TcpConnectionStream(network.TcpA.Connect(network.B.LocalAddress, HttpsPort), activity);
        var thumbprint = EcdsaCertificate.Value.Thumbprint;
        var client = Task.Run(async () =>
        {
            await using var ssl = new SslStream(stream);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "tls.test", EnabledSslProtocols = protocol,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                RemoteCertificateValidationCallback = (_, certificate, _, _) => certificate is X509Certificate2 c && c.Thumbprint == thumbprint,
            });
            await ssl.WriteAsync(Ping);
            var reply = new byte[Ping.Length];
            await ssl.ReadExactlyAsync(reply);
            await ssl.ShutdownAsync(); // Sends close_notify.
            return (ssl.SslProtocol, ssl.NegotiatedCipherSuite, ssl.NegotiatedApplicationProtocol.ToString(), reply);
        });
        RunProtocolThread(network, client, activity, stream);
        var (negotiated, suite, alpn, reply) = client.Result;
        var ours = server!;
        var expected = protocol == SslProtocols.Tls13 ? TlsVersion.Tls13 : TlsVersion.Tls12;
        Check(negotiated == protocol && ours.Version == expected && alpn == "h2" && ours.ApplicationProtocol == "h2",
            $"Negotiated {negotiated} {suite} ALPN '{alpn}'");
        Check(ours.CipherSuite == (expected == TlsVersion.Tls13 ? TlsCipherSuite.TlsAes128GcmSha256 : TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256) &&
              (ushort)suite == (ushort)ours.CipherSuite!, $"Cipher suite {suite} / {ours.CipherSuite}");
        Check(reply.SequenceEqual(Ping.Reverse()), "Echo corrupted");
        RunProtocolThread(network, Task.CompletedTask, activity, stream, () => ours.PeerClosed);
        Console.WriteLine($"      {Describe(protocol)}: {suite}, group {ours.KeyExchangeGroup}, HelloRetryRequest {ours.HelloRetryRequested}, " +
                          $"extended master secret {ours.ExtendedMasterSecret}");
    }

    /// <summary>Our <see cref="TlsConnection"/> as the client, SslStream as an echo server.</summary>
    private static void OurClientToSslStreamServer(SslProtocols protocol)
    {
        var network = new TcpTests.Network();
        using var activity = new SemaphoreSlim(0);
        TcpConnection? accepted = null;
        network.TcpB.Listen(HttpsPort, tcp => accepted = tcp);
        var options = ClientOptions() with { ApplicationProtocols = ["h2"] };
        var client = TlsConnection.AuthenticateAsClient(network.TcpA.Connect(network.B.LocalAddress, HttpsPort), options);
        network.Pump();
        var stream = new TcpConnectionStream(accepted!, activity);
        // macOS keychain-backed SslStream servers need the key in a persisted (PKCS #12-imported) form.
        var certificate = X509CertificateLoader.LoadPkcs12(EcdsaCertificate.Value.Export(X509ContentType.Pkcs12), null);
        var server = Task.Run(async () =>
        {
            await using var ssl = new SslStream(stream);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate, EnabledSslProtocols = protocol, ApplicationProtocols = [SslApplicationProtocol.Http2],
            });
            var request = new byte[Ping.Length];
            await ssl.ReadExactlyAsync(request);
            await ssl.WriteAsync(request.Reverse().ToArray());
            return (ssl.SslProtocol, ssl.NegotiatedCipherSuite, ssl.NegotiatedApplicationProtocol.ToString());
        });
        var reply = new List<byte>();
        client.HandshakeCompleted += c => c.Send(Ping);
        client.DataAvailable += c => { var bytes = new byte[c.Available]; c.Read(bytes); reply.AddRange(bytes); };
        RunProtocolThread(network, server, activity, stream, () => reply.Count == Ping.Length);
        var (negotiated, suite, alpn) = server.Result;
        var expected = protocol == SslProtocols.Tls13 ? TlsVersion.Tls13 : TlsVersion.Tls12;
        Check(negotiated == protocol && client.Version == expected && client.ApplicationProtocol == "h2" && alpn == "h2",
            $"Negotiated {negotiated} {suite} ALPN '{alpn}'; ours {client.Version} {client.FailureReason}");
        Check((ushort)suite == (ushort)client.CipherSuite!, $"Cipher suite {suite} / {client.CipherSuite}");
        Check(reply.SequenceEqual(Ping.Reverse()), "Echo corrupted");
        Console.WriteLine($"      {Describe(protocol)}: {suite}, group {client.KeyExchangeGroup}, extended master secret {client.ExtendedMasterSecret}");
    }

    /// <summary>
    /// Our client over the in-memory TCP stack; the server end's bytes are bridged to a real loopback socket where
    /// <c>openssl s_server -www</c> answers an HTTP request with a status page.
    /// </summary>
    private static void OurClientToOpenSslServer(string openssl, TlsVersion version)
    {
        var directory = Directory.CreateTempSubdirectory("tls-interop-");
        var port = FreeLoopbackPort();
        using var process = StartOpenSslServer(openssl, directory.FullName, port, version);
        try
        {
            var network = new TcpTests.Network();
            using var activity = new SemaphoreSlim(0);
            TcpConnection? accepted = null;
            network.TcpB.Listen(HttpsPort, tcp => accepted = tcp);
            var client = TlsConnection.AuthenticateAsClient(network.TcpA.Connect(network.B.LocalAddress, HttpsPort),
                ClientOptions() with { ApplicationProtocols = ["h2"] });
            network.Pump();
            var bridge = new TcpConnectionStream(accepted!, activity);
            using var socket = new System.Net.Sockets.TcpClient();
            socket.Connect(System.Net.IPAddress.Loopback, port);
            var socketStream = socket.GetStream();
            var copying = Task.WhenAll(bridge.CopyToAsync(socketStream), socketStream.CopyToAsync(bridge));
            var reply = new List<byte>();
            client.HandshakeCompleted += c => c.Send("GET / HTTP/1.0\r\n\r\n"u8);
            client.DataAvailable += c => { var bytes = new byte[c.Available]; c.Read(bytes); reply.AddRange(bytes); };
            RunProtocolThread(network, Task.CompletedTask, activity, bridge,
                () => client.FailureReason is not null || System.Text.Encoding.ASCII.GetString([.. reply]).Contains("</HTML>", StringComparison.OrdinalIgnoreCase));
            Check(client.FailureReason is null, $"Client failed: {client.FailureReason}");
            Check(client.Version == version && client.ApplicationProtocol == "h2" && System.Text.Encoding.ASCII.GetString([.. reply]).StartsWith("HTTP/1.0 200"),
                $"Negotiated {client.Version} ALPN {client.ApplicationProtocol}");
            Console.WriteLine($"      {version}: {client.CipherSuite}, group {client.KeyExchangeGroup}, scheme {client.SignatureScheme}, " +
                              $"HelloRetryRequest {client.HelloRetryRequested}, extended master secret {client.ExtendedMasterSecret}");
        }
        finally
        {
            if (!process.HasExited) process.Kill();
            directory.Delete(recursive: true);
        }
    }

    /// <summary>An OpenSSL 3 binary on PATH or in the usual Homebrew locations; LibreSSL's s_server is not enough.</summary>
    private static string? FindOpenSsl()
    {
        var candidates = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Select(directory => Path.Combine(directory, "openssl"))
            .Concat(["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"]);
        foreach (var candidate in candidates.Where(File.Exists))
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo(candidate, "version") { RedirectStandardOutput = true })!;
                if (process.StandardOutput.ReadToEnd().StartsWith("OpenSSL 3")) return candidate;
            }
            catch (System.ComponentModel.Win32Exception) { }
        }
        return null;
    }

    /// <summary>Starts <c>s_server</c> with our test certificate for one connection and waits until it is listening.</summary>
    private static Process StartOpenSslServer(string openssl, string directory, int port, TlsVersion version)
    {
        var certificate = EcdsaCertificate.Value;
        var certificatePath = Path.Combine(directory, "server.pem");
        var keyPath = Path.Combine(directory, "server.key");
        File.WriteAllText(certificatePath, certificate.ExportCertificatePem());
        using (var key = certificate.GetECDsaPrivateKey()!) File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        var arguments = $"s_server -accept 127.0.0.1:{port} -naccept 1 -cert \"{certificatePath}\" -key \"{keyPath}\" " +
                        $"{(version == TlsVersion.Tls13 ? "-tls1_3" : "-tls1_2")} -alpn h2 -www";
        var process = Process.Start(new ProcessStartInfo(openssl, arguments) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        var ready = new TaskCompletionSource();
        process.OutputDataReceived += (_, line) => { if (line.Data?.StartsWith("ACCEPT") == true) ready.TrySetResult(); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (!ready.Task.Wait(InteropTimeout)) throw new TimeoutException("openssl s_server did not start listening.");
        return process;
    }

    /// <summary>A loopback port that was free a moment ago.</summary>
    private static int FreeLoopbackPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>
    /// Acts as the stack's protocol thread until <paramref name="work"/> completes and <paramref name="until"/> holds:
    /// services the stream adapter, delivers packets, and when idle advances the fake clock so TCP timers run.
    /// </summary>
    private static void RunProtocolThread(TcpTests.Network network, Task work, SemaphoreSlim activity, TcpConnectionStream stream, Func<bool>? until = null)
    {
        var timer = Stopwatch.StartNew();
        while (!work.IsCompleted || !(until?.Invoke() ?? true))
        {
            if (timer.Elapsed > InteropTimeout) throw new TimeoutException("SslStream interop did not finish.");
            var progress = stream.Service();
            if (network.Queue.Count > 0) { network.Pump(); progress = true; }
            if (!progress && !activity.Wait(TimeSpan.FromMilliseconds(5))) network.AdvanceMilliseconds(5);
        }
        work.GetAwaiter().GetResult(); // Surface SslStream's exception, if any.
    }
}
