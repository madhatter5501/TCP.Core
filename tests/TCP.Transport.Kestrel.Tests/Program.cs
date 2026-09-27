using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;
using TCP.L5_7.Application.Http2;
using TCP.Transport.Kestrel.Tests;

// Kestrel served entirely through TCP.Core over a virtual Ethernet link, with a second TCP.Core stack as
// the client. Deterministic: this validates the adapter, not interoperability with an OS TCP stack.

var passed = 0;
var failed = 0;
var testTimeout = TimeSpan.FromSeconds(90);
var filter = Environment.GetEnvironmentVariable("TEST_FILTER"); // Run only tests whose name contains this text.
TestNetwork? current = null;

async Task Test(string name, Func<Task> body)
{
    if (!string.IsNullOrEmpty(filter) && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) return;
    try
    {
        await body().WaitAsync(testTimeout);
        passed++;
        Console.WriteLine($"PASS: {name}");
    }
    catch (Exception error)
    {
        failed++;
        Console.WriteLine($"FAIL: {name}\n{error}");
        if (current is not null) Console.WriteLine("Last frames:\n  " + string.Join("\n  ", current.Link.Log.TakeLast(120)));
    }
}

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static async Task WaitUntilAsync(Func<Task<bool>> condition, string message, int seconds = 10)
{
    var deadline = DateTime.UtcNow.AddSeconds(seconds);
    while (!await condition())
    {
        if (DateTime.UtcNow > deadline) throw new TimeoutException(message);
        await Task.Delay(50);
    }
}

await using (var network = await TestNetwork.StartAsync())
{
    current = network;
    var serverResets = () => network.Link.Log.Count(frame => frame.FromServer && frame.Flags.HasFlag(TcpFlags.Rst));

    await Test("Kestrel serves only the TCP.Core endpoint (no OS socket fallback)", () =>
    {
        var addresses = network.App.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses;
        Check(addresses.Count == 2 && addresses.All(address => address.Contains("tcp-core://", StringComparison.Ordinal)),
            $"Unexpected server addresses: {string.Join(", ", addresses)}");
        return Task.CompletedTask;
    });

    await Test("GET closes gracefully: server FIN, server-side TIME-WAIT, never a reset", async () =>
    {
        var resetsBefore = serverResets();
        var client = await network.ConnectAsync();
        await client.SendAsync(HttpRequests.Get("/health"));
        var response = await client.ReadResponseAsync();
        Check(response.Status == 200 && response.BodyText == TestNetwork.HealthBody, $"Unexpected response {response.Status}: {response.BodyText}");
        await client.WaitForEndOfStreamAsync();
        Check(client.FailureReason is null, $"Connection failed: {client.FailureReason}");
        await client.CloseAsync();
        // The server closed first, so TcpHost (not Kestrel) must hold the connection in TIME-WAIT.
        await WaitUntilAsync(async () => await client.GetStateAsync() == TcpState.Closed, "Client did not finish closing");
        Check(client.FailureReason is null, $"Client close failed: {client.FailureReason}");
        Check(await network.RunOnServerAsync(() => network.ServerStack.Tcp.Connections.Any(connection =>
            connection.RemotePort == client.LocalPort && connection.State == TcpState.TimeWait)), "Server did not keep the connection in TIME-WAIT");
        await Task.Delay(TimeSpan.FromSeconds(1)); // A late reset would arrive here.
        Check(serverResets() == resetsBefore, "Server reset a gracefully completed connection");
    });

    await Test("keep-alive serves sequential requests on one connection", async () =>
    {
        var client = await network.ConnectAsync();
        await client.SendAsync(HttpRequests.Get("/health", keepAlive: true));
        Check((await client.ReadResponseAsync()).BodyText == TestNetwork.HealthBody, "First keep-alive response differs");
        await client.SendAsync(HttpRequests.Get("/api/transport", keepAlive: true));
        var second = await client.ReadResponseAsync();
        Check(second.Status == 200 && second.BodyText.Contains("\"mode\":\"tcp-core\"", StringComparison.Ordinal), $"Transport status differs: {second.BodyText}");
        Check(await client.GetStateAsync() == TcpState.Established, "Keep-alive connection did not stay open");
        await client.CloseAsync();
        await client.WaitForEndOfStreamAsync();
        Check(client.FailureReason is null, $"Keep-alive close failed: {client.FailureReason}");
    });

    await Test("slow reader closes the TCP window and the response resumes intact", async () =>
    {
        const int length = 200_000;
        network.Link.Log.Clear();
        var client = await network.ConnectAsync(receiveCapacity: 2048, manualRead: true);
        await client.SendAsync(HttpRequests.Get($"/large?bytes={length}"));
        var response = client.ReadResponseAsync(TimeSpan.FromSeconds(60));
        while (!response.IsCompleted)
        {
            await client.ReadSomeAsync(256);
            await Task.Delay(5);
        }
        Check((await response).Body.AsSpan().SequenceEqual(TestPayload.Create(length)), "Slow-reader body differs");
        Check(network.Link.Log.Any(frame => !frame.FromServer && frame.IsTcp && frame.Window == 0), "Client never advertised a zero window");
    });

    await Test("response larger than TCP's send buffer streams through Kestrel backpressure", async () =>
    {
        var length = TcpConnection.MaximumSendBuffer + 500_000;
        var client = await network.ConnectAsync();
        await client.SendAsync(HttpRequests.Get($"/large?bytes={length}"));
        var response = await client.ReadResponseAsync(TimeSpan.FromSeconds(60));
        Check(response.Body.AsSpan().SequenceEqual(TestPayload.Create(length)), "Large body differs");
        await client.WaitForEndOfStreamAsync();
    });

    await Test("request body split across many small segments, then FIN, is fully echoed", async () =>
    {
        const int chunk = 97;
        var body = TestPayload.Create(20_000);
        network.Link.Log.Clear();
        var client = await network.ConnectAsync(noDelay: true);
        await client.SendAsync(HttpRequests.PostHeader("/echo", body.Length, "application/octet-stream"));
        for (var offset = 0; offset < body.Length; offset += chunk)
            await client.SendAsync(body.AsMemory(offset, Math.Min(chunk, body.Length - offset)));
        await client.CloseAsync(); // FIN right behind the last body bytes.
        var response = await client.ReadResponseAsync();
        Check(response.Status == 200 && response.Body.AsSpan().SequenceEqual(body), "Echoed body differs");
        var clientDataSegments = network.Link.Log.Count(frame => !frame.FromServer && frame.IsTcp && frame.PayloadLength > 0);
        Check(clientDataSegments > body.Length / 1460, $"Request was not split ({clientDataSegments} data segments)");
        await client.WaitForEndOfStreamAsync();
    });

    await Test("loss, corruption, duplication and reordering are repaired end to end", async () =>
    {
        const int length = 300_000;
        var serverData = 0; var clientSegments = 0; var faults = 0;
        network.Link.Fault = frame =>
        {
            if (!frame.IsTcp) return FrameFault.None;
            FrameFault fault;
            if (frame.FromServer && frame.PayloadLength > 0)
            {
                var n = Interlocked.Increment(ref serverData);
                // Sparse, deterministic faults. Retransmissions count too, so a lost retransmission is possible;
                // without SACK only the retransmission timer recovers that, so keep the rate realistic.
                fault = n % 29 == 0 ? FrameFault.Drop : n % 31 == 0 ? FrameFault.Corrupt
                    : n % 13 == 0 ? FrameFault.Reorder : n % 7 == 0 ? FrameFault.Duplicate : FrameFault.None;
            }
            else
            {
                var n = Interlocked.Increment(ref clientSegments);
                fault = n % 17 == 0 ? FrameFault.Reorder : n % 5 == 0 ? FrameFault.Duplicate : FrameFault.None;
            }
            if (fault != FrameFault.None) Interlocked.Increment(ref faults);
            return fault;
        };
        try
        {
            var client = await network.ConnectAsync();
            await client.SendAsync(HttpRequests.Get($"/large?bytes={length}"));
            var response = await client.ReadResponseAsync(TimeSpan.FromSeconds(60));
            Check(response.Body.AsSpan().SequenceEqual(TestPayload.Create(length)), "Body differs after faults");
            Check(faults > 20, $"Too few faults injected ({faults})");
        }
        finally { network.Link.Fault = _ => FrameFault.None; }
    });

    await Test("client reset mid-response releases the server connection", async () =>
    {
        var client = await network.ConnectAsync(manualRead: true);
        await client.SendAsync(HttpRequests.Get("/large?bytes=1000000"));
        await Task.Delay(200);
        await client.ReadSomeAsync(20_000);
        await client.AbortAsync();
        await WaitUntilAsync(() => network.RunOnServerAsync(() =>
            network.ServerStack.Tcp.Connections.All(connection => connection.RemotePort != client.LocalPort)),
            "Server kept the reset connection");
        var next = await network.ConnectAsync();
        await next.SendAsync(HttpRequests.Get("/health"));
        Check((await next.ReadResponseAsync()).BodyText == TestNetwork.HealthBody, "Server unhealthy after a reset");
    });

    await Test("Explorer page, script, deep links and simulation API are served through TCP.Core", async () =>
    {
        var client = await network.ConnectAsync();
        await client.SendAsync(HttpRequests.Get("/", keepAlive: true));
        var page = await client.ReadResponseAsync();
        Check(page.Status == 200 && page.BodyText.Contains("<div id=\"root\">", StringComparison.Ordinal), "Explorer page missing");
        // The bundle name is content-hashed by the client build; follow the page's own reference.
        var scriptPath = Regex.Match(page.BodyText, "src=\"(/assets/[^\"]+\\.js)\"").Groups[1].Value;
        Check(scriptPath.Length > 0, "Explorer page does not reference a script bundle");
        await client.SendAsync(HttpRequests.Get(scriptPath, keepAlive: true));
        var script = await client.ReadResponseAsync();
        Check(script.Status == 200 && script.Headers["Content-Type"].Contains("javascript", StringComparison.Ordinal), "Explorer script missing");
        await client.SendAsync(HttpRequests.Get("/layers/network/gotchas", keepAlive: true));
        var deepLink = await client.ReadResponseAsync();
        Check(deepLink.Status == 200 && deepLink.BodyText == page.BodyText, "Client route did not fall back to the app shell");
        await client.SendAsync(HttpRequests.Get("/api/missing", keepAlive: true));
        Check((await client.ReadResponseAsync()).Status == 404, "Unknown API path returned the app shell");
        await client.SendAsync(HttpRequests.Post("/api/simulate", Encoding.UTF8.GetBytes("{\"scenario\":\"ping\"}"), "application/json"));
        var simulation = await client.ReadResponseAsync();
        Check(simulation.Status == 200 && simulation.BodyText.Contains("\"replyVerified\":true", StringComparison.Ordinal), $"Simulation failed: {simulation.BodyText}");
    });
}

// ---- HTTP/2 over cleartext (h2c) with prior knowledge ----------------------------------------------------
// No TLS means no ALPN, so the client must already know the server speaks HTTP/2: HttpClient opens with the
// connection preface on TestNetwork.H2cPort, an Http2-only endpoint. Frames are decoded from the bytes that
// actually crossed the TCP.Core connection.

await using (var h2 = await TestNetwork.StartAsync())
{
    current = h2;
    static bool IsResponseEnd(Http2WireFrame wire, int stream) =>
        !wire.FromClient && wire.Frame.StreamId == stream && wire.Frame.HasFlag(Http2FrameFlags.EndStream) &&
        wire.Frame.Type is Http2FrameType.Data or Http2FrameType.Headers;

    await Test("h2c prior knowledge: the Http2 endpoint serves HTTP/2 beside the HTTP/1.1 endpoint", async () =>
    {
        using var client = h2.CreateHttp2Client();
        using var health = await client.Http.GetAsync("/health");
        Check(health.Version == HttpVersion.Version20, $"Negotiated HTTP/{health.Version}");
        Check(await health.Content.ReadAsStringAsync() == TestNetwork.HealthBody, "HTTP/2 health body differs");
        var echoed = await (await client.Http.PostAsync("/echo", new ByteArrayContent(TestPayload.Create(5_000)))).Content.ReadAsByteArrayAsync();
        Check(echoed.AsSpan().SequenceEqual(TestPayload.Create(5_000)), "HTTP/2 echo differs");
        var transport = await client.Http.GetStringAsync("/api/transport");
        Check(transport.Contains("\"mode\":\"tcp-core\"", StringComparison.Ordinal), $"Transport status differs: {transport}");

        var frames = client.SingleConnection.Frames(); // The reader has already checked the preface and SETTINGS-first rule.
        Check(frames.First(frame => !frame.FromClient).Frame.Type == Http2FrameType.Settings, "Server did not open with SETTINGS");
        Check(frames.Any(frame => frame.FromClient && frame.Frame is { Type: Http2FrameType.Settings } settings && settings.HasFlag(Http2FrameFlags.Ack)),
            "Client never acknowledged the server's SETTINGS");
        var requestStreams = frames.Where(frame => frame.FromClient && frame.Frame.Type == Http2FrameType.Headers).Select(frame => frame.Frame.StreamId).ToList();
        Check(requestStreams.SequenceEqual([1, 3, 5]), $"Requests used streams {string.Join(", ", requestStreams)}, expected 1, 3, 5");

        var http1 = await h2.ConnectAsync();
        await http1.SendAsync(HttpRequests.Get("/health"));
        Check((await http1.ReadResponseAsync()).BodyText == TestNetwork.HealthBody, "HTTP/1.1 endpoint stopped working");
    });

    await Test("h2c endpoint answers an HTTP/1.1 request with 400 and closes", async () =>
    {
        // An Http2-only endpoint that sees an HTTP/1.x request line explains itself in HTTP/1.1, then hangs up.
        var http1 = await h2.ConnectAsync(port: TestNetwork.H2cPort);
        await http1.SendAsync(HttpRequests.Get("/health", keepAlive: true));
        var response = await http1.ReadResponseAsync();
        Check(response.Status == 400 && response.BodyText.Contains("HTTP/2 only endpoint", StringComparison.Ordinal),
            $"Unexpected response {response.Status}: {response.BodyText}");
        await http1.WaitForEndOfStreamAsync();
    });

    await Test("h2c multiplexing: a stream the server holds open does not block others on the same TCP connection", async () =>
    {
        using var client = h2.CreateHttp2Client();
        var held = client.Http.GetStringAsync("/gate/held");
        var others = Enumerable.Range(0, 12).Select(async i => i % 2 == 0
            ? await client.Http.GetStringAsync("/health") == TestNetwork.HealthBody
            : (await client.Http.GetByteArrayAsync($"/large?bytes={40_000 + i}")).AsSpan().SequenceEqual(TestPayload.Create(40_000 + i))).ToList();
        Check((await Task.WhenAll(others)).All(ok => ok), "A multiplexed response differs");
        Check(!held.IsCompleted, "The held request completed before its gate opened");
        h2.OpenGate("held");
        Check(await held == "held", "Held response differs");

        // Read the order of completion off the wire: every other stream ended before the held one.
        var frames = client.SingleConnection.Frames();
        var heldStream = frames.Single(frame => !frame.FromClient && frame.Frame.Type == Http2FrameType.Data &&
            frame.Frame.Data.Span.SequenceEqual("held"u8)).Frame.StreamId;
        var completionOrder = frames.Where(frame => !frame.FromClient && frame.Frame.HasFlag(Http2FrameFlags.EndStream) &&
            frame.Frame.Type is Http2FrameType.Data or Http2FrameType.Headers).Select(frame => frame.Frame.StreamId).ToList();
        Check(completionOrder.Count == others.Count + 1 && completionOrder[^1] == heldStream,
            $"Stream {heldStream} was held, but streams completed in order {string.Join(", ", completionOrder)}");
    });

    await Test("h2c multiplexing: concurrent large responses interleave DATA frames on one connection", async () =>
    {
        using var client = h2.CreateHttp2Client();
        var lengths = Enumerable.Range(0, 6).Select(i => 250_000 + i * 1_000).ToArray();
        var bodies = await Task.WhenAll(lengths.Select(length => client.Http.GetByteArrayAsync($"/large?bytes={length}")));
        for (var i = 0; i < lengths.Length; i++)
            Check(bodies[i].AsSpan().SequenceEqual(TestPayload.Create(lengths[i])), $"Body {i} differs");
        var dataStreams = client.SingleConnection.Frames()
            .Where(frame => !frame.FromClient && frame.Frame.Type == Http2FrameType.Data && frame.Frame.Length > 0)
            .Select(frame => frame.Frame.StreamId).ToList();
        // A run is a sequence of consecutive DATA frames for one stream. More runs than streams means at least one
        // response was paused while another stream's frames went out on the same TCP connection.
        var runs = 1 + dataStreams.Zip(dataStreams.Skip(1)).Count(pair => pair.First != pair.Second);
        Check(dataStreams.Distinct().Count() == lengths.Length, "Not every stream carried DATA");
        Check(runs > lengths.Length, $"DATA frames were not interleaved ({runs} runs for {lengths.Length} streams)");
    });

    await Test("h2c flow control: megabyte bodies both ways stay within every advertised window", async () =>
    {
        const int length = 1_000_000;
        using var client = h2.CreateHttp2Client();
        var body = TestPayload.Create(length);
        var echo = client.Http.PostAsync("/echo", new ByteArrayContent(body));
        var download = client.Http.GetByteArrayAsync($"/large?bytes={length}");
        Check((await (await echo).Content.ReadAsByteArrayAsync()).AsSpan().SequenceEqual(body), "Echoed body differs");
        Check((await download).AsSpan().SequenceEqual(body), "Downloaded body differs");
        var audit = Http2FlowControlAudit.Check(client.SingleConnection.Frames());
        Check(audit.ClientDataBytes >= length && audit.ServerDataBytes >= 2L * length, $"Too little DATA: {audit}");
        // Each side sent far more than the 65,535-byte default windows, so the other had to keep granting credit.
        Check(audit.ServerWindowUpdates > 0 && audit.ClientWindowUpdates > 0, $"No WINDOW_UPDATE credit was needed: {audit}");
    });

    await Test("h2c flow control: an unread stream stalls at its window while TCP and other streams keep flowing", async () =>
    {
        const int length = 1_000_000;
        const int streamWindow = Http2Constants.DefaultInitialWindowSize;
        using var client = h2.CreateHttp2Client(initialStreamWindowSize: streamWindow);
        using var response = await client.Http.GetAsync($"/large?bytes={length}", HttpCompletionOption.ResponseHeadersRead);
        var connection = client.SingleConnection;
        var stalledStream = connection.Frames().First(frame => frame.FromClient && frame.Frame.Type == Http2FrameType.Headers).Frame.StreamId;
        long Delivered() => connection.Frames().Where(frame => !frame.FromClient && frame.Frame.StreamId == stalledStream).Sum(frame => frame.Frame.FlowControlledLength);
        long previous = -1;
        await WaitUntilAsync(async () =>
        {
            var now = Delivered();
            var settled = now == previous && now > 0;
            previous = now;
            await Task.Delay(300);
            return settled;
        }, "The unread stream never stopped receiving");
        Check(previous <= streamWindow, $"Server sent {previous} bytes on an unread stream with a {streamWindow}-byte window");
        // HTTP/2 flow control stopped this stream, not TCP: the connection is open and other streams still run.
        Check(await connection.Client.GetStateAsync() == TcpState.Established, "TCP connection is not established");
        Check(await client.Http.GetStringAsync("/health") == TestNetwork.HealthBody, "A second stream was blocked by the stalled one");
        Check(Delivered() == previous, "The stalled stream advanced without being read");
        var body = await response.Content.ReadAsByteArrayAsync();
        Check(body.AsSpan().SequenceEqual(TestPayload.Create(length)), "Stalled body differs after resuming");
        Http2FlowControlAudit.Check(connection.Frames());
    });

    await Test("h2c over loss, corruption, duplication and reordering: concurrent streams arrive intact", async () =>
    {
        var dataSegments = 0; var controlSegments = 0; var faults = 0;
        h2.Link.Fault = frame =>
        {
            if (!frame.IsTcp) return FrameFault.None;
            FrameFault fault;
            if (frame.PayloadLength > 0)
            {
                // Same sparse, deterministic pattern as the HTTP/1.1 test, applied to data in both directions.
                var n = Interlocked.Increment(ref dataSegments);
                fault = n % 29 == 0 ? FrameFault.Drop : n % 31 == 0 ? FrameFault.Corrupt
                    : n % 13 == 0 ? FrameFault.Reorder : n % 7 == 0 ? FrameFault.Duplicate : FrameFault.None;
            }
            else
            {
                var n = Interlocked.Increment(ref controlSegments);
                fault = n % 17 == 0 ? FrameFault.Reorder : n % 5 == 0 ? FrameFault.Duplicate : FrameFault.None;
            }
            if (fault != FrameFault.None) Interlocked.Increment(ref faults);
            return fault;
        };
        try
        {
            using var client = h2.CreateHttp2Client();
            var upload = TestPayload.Create(150_000);
            var downloads = Enumerable.Range(0, 4).Select(i => client.Http.GetByteArrayAsync($"/large?bytes={100_000 + i}")).ToList();
            var echo = client.Http.PostAsync("/echo", new ByteArrayContent(upload));
            var bodies = await Task.WhenAll(downloads);
            for (var i = 0; i < bodies.Length; i++)
                Check(bodies[i].AsSpan().SequenceEqual(TestPayload.Create(100_000 + i)), $"Download {i} differs after faults");
            Check((await (await echo).Content.ReadAsByteArrayAsync()).AsSpan().SequenceEqual(upload), "Upload echo differs after faults");
            Check(faults > 20, $"Too few faults injected ({faults})");
            Http2FlowControlAudit.Check(client.SingleConnection.Frames());
        }
        finally { h2.Link.Fault = _ => FrameFault.None; }
    });

    await Test("h2c client abort resets one stream (RST_STREAM) and the connection keeps serving", async () =>
    {
        using var client = h2.CreateHttp2Client();
        using (var abandoned = await client.Http.GetAsync("/large?bytes=1000000", HttpCompletionOption.ResponseHeadersRead)) { }
        Check(await client.Http.GetStringAsync("/health") == TestNetwork.HealthBody, "Connection unusable after a stream reset");
        var frames = client.SingleConnection.Frames();
        Check(frames.Any(frame => frame.FromClient && frame.Frame.Type == Http2FrameType.RstStream && frame.Frame.StreamId == 1),
            "Client did not reset the abandoned stream");
        Check(await client.SingleConnection.Client.GetStateAsync() == TcpState.Established, "Stream reset closed the TCP connection");
    });
}

await using (var mixed = await TestNetwork.StartAsync(httpProtocols: HttpProtocols.Http1AndHttp2))
{
    current = mixed;
    await Test("cleartext Http1AndHttp2 endpoint serves HTTP/1.1 and answers the h2 preface with HTTP_1_1_REQUIRED", async () =>
    {
        // Kestrel chooses HTTP/2 on a mixed endpoint only through TLS ALPN; without TLS the choice is HTTP/1.1.
        var http1 = await mixed.ConnectAsync();
        await http1.SendAsync(HttpRequests.Get("/health"));
        Check((await http1.ReadResponseAsync()).BodyText == TestNetwork.HealthBody, "HTTP/1.1 failed on the mixed endpoint");
        using var client = mixed.CreateHttp2Client(port: TestNetwork.HttpPort);
        HttpProtocolException? refusal = null;
        try { await client.Http.GetStringAsync("/health"); }
        catch (HttpRequestException error) { refusal = error.InnerException as HttpProtocolException; }
        Check(refusal?.ErrorCode == (long)Http2ErrorCode.Http11Required, $"Expected HTTP_1_1_REQUIRED, got {refusal?.ErrorCode.ToString() ?? "success"}");
    });
}

await using (var h2Shutdown = await TestNetwork.StartAsync())
{
    current = h2Shutdown;
    await Test("shutdown sends HTTP/2 GOAWAY on an idle h2c connection, then closes TCP", async () =>
    {
        using var client = h2Shutdown.CreateHttp2Client();
        Check(await client.Http.GetStringAsync("/health") == TestNetwork.HealthBody, "Pre-shutdown request failed");
        var connection = client.SingleConnection;
        await h2Shutdown.StopAppAsync();
        await connection.Client.WaitForEndOfStreamAsync(TimeSpan.FromSeconds(10));
        var goAway = connection.Frames().LastOrDefault(frame => !frame.FromClient && frame.Frame.Type == Http2FrameType.GoAway);
        Check(goAway is { Frame.ErrorCode: Http2ErrorCode.NoError } && goAway.Frame.LastStreamId == 1, $"Expected graceful GOAWAY, got {goAway}");
        Check(h2Shutdown.HostService.Failure is null, $"Protocol thread failed: {h2Shutdown.HostService.Failure}");
    });
}

await using (var smallMtu = await TestNetwork.StartAsync(mtu: 576))
{
    current = smallMtu;
    await Test("minimum-reassembly MTU (576) carries a large response without oversized packets", async () =>
    {
        const int length = 100_000;
        var client = await smallMtu.ConnectAsync();
        await client.SendAsync(HttpRequests.Get($"/large?bytes={length}"));
        var response = await client.ReadResponseAsync(TimeSpan.FromSeconds(60));
        Check(response.Body.AsSpan().SequenceEqual(TestPayload.Create(length)), "Small-MTU body differs");
        var largest = smallMtu.Link.Log.Max(frame => frame.IPv4Length);
        Check(largest <= 576, $"IPv4 packet of {largest} bytes exceeded the 576-byte MTU");
    });
}

await using (var shutdown = await TestNetwork.StartAsync())
{
    current = shutdown;
    await Test("shutdown closes an idle keep-alive connection and stops the protocol thread", async () =>
    {
        var client = await shutdown.ConnectAsync();
        await client.SendAsync(HttpRequests.Get("/health", keepAlive: true));
        Check((await client.ReadResponseAsync()).BodyText == TestNetwork.HealthBody, "Pre-shutdown request failed");
        await shutdown.StopAppAsync();
        await client.WaitForEndOfStreamAsync(TimeSpan.FromSeconds(10));
        Check(shutdown.HostService.Failure is null, $"Protocol thread failed: {shutdown.HostService.Failure}");
        var rejected = false;
        try { await shutdown.HostService.RunOnProtocolThreadAsync(() => { }, CancellationToken.None); }
        catch (IOException) { rejected = true; }
        Check(rejected, "Protocol thread still accepted work after shutdown");
    });
}

Console.WriteLine($"{passed} Kestrel transport tests passed, {failed} failed.");
return failed == 0 ? 0 : 1;
