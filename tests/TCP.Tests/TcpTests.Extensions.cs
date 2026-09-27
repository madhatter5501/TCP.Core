using System.Net;
using TCP.Checksums;
using TCP.L3.Network;
using TCP.L3.Network.Icmp;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Authentication;
using TCP.L4.Transport.Tcp.Congestion;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.Tests;

/// <summary>Regression tests for the TCP extensions: options, ACK policy, loss recovery, congestion control and security.</summary>
internal static partial class TcpTests
{
    private static readonly TcpSettings Plain = new()
    {
        WindowScaling = false, Timestamps = false, SelectiveAcknowledgments = false,
        ExplicitCongestionNotification = false, FastOpen = false
    };

    private static void RunExtensionTests(Action<string, Action> test)
    {
        test("option codec round-trips every supported option and rejects malformed lengths", () =>
        {
            var writer = new TcpOptionWriter();
            writer.TryAdd(TcpOptionWriter.MaximumSegmentSize(1460));
            writer.TryAdd(TcpOptionWriter.SackPermittedAndTimestamp(new TcpTimestamp(7, 9)));
            writer.TryAdd(TcpOptionWriter.WindowScale(7));
            writer.TryAdd(TcpOptionWriter.UserTimeout(TimeSpan.FromSeconds(90)));
            writer.TryAdd(TcpOptionWriter.FastOpen([1, 2, 3, 4, 5, 6, 7, 8]));
            var options = TcpOptions.Parse(writer.ToArray());
            Check(writer.Length == 36 && options.MaximumSegmentSize == 1460 && options.SackPermitted &&
                  options.Timestamp == new TcpTimestamp(7, 9) && options.WindowScale == 7 &&
                  options.UserTimeout == TimeSpan.FromSeconds(90) && options.FastOpenCookie!.Length == 8, "Option round trip failed");
            Check(writer.TryAdd(TcpOptionWriter.Timestamp(new TcpTimestamp(1, 1))) is null, "Writer exceeded 40 bytes");
            var sack = new TcpOptionWriter();
            sack.TryAdd(TcpOptionWriter.Sack([new SackBlock(100, 200), new SackBlock(300, 400)]));
            Check(TcpOptions.Parse(sack.ToArray()).SackBlocks.SequenceEqual([new SackBlock(100, 200), new SackBlock(300, 400)]), "SACK round trip failed");
            Check(TcpOptions.Parse(new TcpOptionWriter().ToArray()) == TcpOptions.None, "Empty options not shared");
            var hours = new TcpOptionWriter(); hours.TryAdd(TcpOptionWriter.UserTimeout(TimeSpan.FromHours(10)));
            Check(TcpOptions.Parse(hours.ToArray()).UserTimeout == TimeSpan.FromHours(10), "Minute-granularity user timeout lost");
            Throws(() => TcpOptions.Parse([3, 4, 0, 0]));
            Throws(() => TcpOptions.Parse([5, 3, 0, 0]));
            Throws(() => TcpOptions.Parse([34, 4, 0, 0]));
            Throws(() => TcpOptions.Parse([8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        });
        test("codec checksums IPv6 segments over the RFC 8200 pseudo-header", () =>
        {
            var a = IPAddress.Parse("2001:db8::1"); var b = IPAddress.Parse("2001:db8::2");
            var segment = new TcpSegment(1234, 80, 1, 0, TcpFlags.Syn, 65535, "hi"u8.ToArray());
            var bytes = segment.Serialize(a, b);
            var pseudo = new byte[40 + bytes.Length];
            a.GetAddressBytes().CopyTo(pseudo, 0); b.GetAddressBytes().CopyTo(pseudo, 16);
            pseudo[35] = (byte)bytes.Length; pseudo[39] = 6; bytes.CopyTo(pseudo, 40);
            Check(InternetChecksum.IsValid(pseudo), "IPv6 pseudo-header checksum mismatch");
            Check(TcpSegment.Parse(a, b, bytes).Payload.Span.SequenceEqual("hi"u8), "IPv6 parse failed");
            Throws(() => TcpSegment.Parse(a, IPAddress.Parse("2001:db8::3"), bytes));
            Throws(() => segment.Serialize(a, IPAddress.Parse("192.0.2.1")));
        });
        test("AES-CMAC matches the RFC 4493 test vectors", () =>
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var message = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
            Check(Convert.ToHexString(AesCmac.Compute(key, [])) == "BB1D6929E95937287FA37D129B756746", "Empty-message CMAC wrong");
            Check(Convert.ToHexString(AesCmac.Compute(key, message.AsSpan(0, 16))) == "070A16B46B4D4144F79BDD9DD04A287C", "One-block CMAC wrong");
            Check(Convert.ToHexString(AesCmac.Compute(key, message)) == "DFA66747DE9AE63030CA32611497C827", "Partial-block CMAC wrong");
        });
        test("extensions are negotiated only when both SYNs offer them", () =>
        {
            var n = new Network(); var (a, b) = n.Connect();
            Check(a.WindowScalingEnabled && a.TimestampsEnabled && a.SelectiveAcknowledgmentsEnabled && a.ExplicitCongestionNotificationEnabled &&
                  b.WindowScalingEnabled && b.TimestampsEnabled && b.SelectiveAcknowledgmentsEnabled && b.ExplicitCongestionNotificationEnabled,
                "Default extensions not negotiated");
            var m = new Network(settingsB: Plain with { FastOpen = true }); var (c, d) = m.Connect();
            Check(!c.WindowScalingEnabled && !c.TimestampsEnabled && !c.SelectiveAcknowledgmentsEnabled && !c.ExplicitCongestionNotificationEnabled &&
                  !d.WindowScalingEnabled && !d.TimestampsEnabled && c.MaximumSegmentSize == 1460, "Extension used without the peer's offer");
            var synAck = m.History.Select(Parse).First(s => s.Has(TcpFlags.Syn | TcpFlags.Ack) && s.Has(TcpFlags.Ack));
            var offered = synAck.ReadOptions();
            Check(offered.WindowScale is null && offered.Timestamp is null && !offered.SackPermitted && !synAck.Has(TcpFlags.Ece), "SYN-ACK offered an unrequested option");
        });
        test("window scaling carries a 1 MiB window through the 16-bit field", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(capacity: 1 << 20);
            Check(b.ReceiveWindow > ushort.MaxValue, "Receive window not above 64 KiB");
            var data = new byte[1_500_000]; Random.Shared.NextBytes(data);
            var received = new List<byte>();
            a.Send(data);
            for (var i = 0; i < 400 && received.Count < data.Length; i++)
            {
                n.Pump(); if (i % 4 == 0) received.AddRange(ReadAll(b));
                n.AdvanceMilliseconds(10);
            }
            received.AddRange(ReadAll(b));
            Check(received.SequenceEqual(data), "Scaled transfer corrupted");
            Check(n.History.Select(Parse).Where(s => !s.Has(TcpFlags.Syn) && s.SourcePort == 80).All(s => s.Window <= ushort.MaxValue) &&
                  n.History.Select(Parse).Any(s => s.SourcePort == 80 && !s.Has(TcpFlags.Syn) && s.Window << 5 > ushort.MaxValue), "Window field not scaled");
        });
        test("delayed ACK acknowledges every second full segment or after the timeout", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.NoDelay = true;
            n.History.Clear(); a.Send(new byte[100]); n.Pump();
            Check(AcksFrom(n, n.B) == 0 && a.BufferedSendBytes == 100, "Single small segment acknowledged immediately");
            n.AdvanceMilliseconds(199); Check(AcksFrom(n, n.B) == 0, "Delayed ACK sent early");
            n.AdvanceMilliseconds(1); Check(AcksFrom(n, n.B) == 1 && a.BufferedSendBytes == 0, "Delayed ACK timer did not fire");
            ReadAll(b); n.History.Clear();
            a.Send(new byte[2 * a.MaximumSegmentSize]); n.Pump();
            Check(AcksFrom(n, n.B) == 1 && a.BufferedSendBytes == 0, "Two full segments did not draw exactly one ACK");
            n.History.Clear(); var gap = new byte[3 * a.MaximumSegmentSize]; a.Send(gap);
            var sent = n.Queue.ToArray(); n.Queue.Clear(); n.Queue.Enqueue(sent[1]); n.DeliverNext();
            Check(AcksFrom(n, n.B) == 1, "Out-of-order segment not acknowledged immediately");
        });
        test("keep-alive probes an idle peer and releases one that stops answering", () =>
        {
            var n = new Network(settings: new TcpSettings { KeepAlive = true }); var (a, _) = n.Connect();
            n.Clock.Advance(TimeSpan.FromHours(2)); n.A.Tick();
            var probe = Parse(n.Queue.Single().Packet);
            Check(probe.SequenceNumber == a.NextSendSequence - 1 && probe.Payload.IsEmpty, "Keep-alive probe malformed");
            n.Pump(); Check(a.State == TcpState.Established && n.Queue.Count == 0, "Answered keep-alive failed the connection");
            n.Clock.Advance(TimeSpan.FromHours(2)); n.A.Tick(); n.Queue.Clear();
            for (var i = 0; i < 12 && a.State != TcpState.Closed; i++) { n.Clock.Advance(TimeSpan.FromSeconds(75)); n.A.Tick(); n.Queue.Clear(); }
            Check(a.State == TcpState.Closed && a.FailureReason!.Contains("keep-alive"), "Dead peer kept alive");
            var quiet = new Network(); var (c, _) = quiet.Connect();
            quiet.Clock.Advance(TimeSpan.FromHours(3)); quiet.A.Tick(); Check(quiet.Queue.Count == 0 && !c.KeepAlive, "Keep-alive on by default");
        });
        test("user timeout aborts stalled data and is advertised to a willing peer", () =>
        {
            var n = new Network(); var (a, _) = n.Connect(); a.UserTimeout = TimeSpan.FromSeconds(30); a.Send("stalled"u8);
            for (var i = 0; i < 60 && a.State != TcpState.Closed; i++) { n.Queue.Clear(); n.Clock.Advance(TimeSpan.FromSeconds(1)); n.A.Tick(); }
            Check(a.State == TcpState.Closed && a.FailureReason!.Contains("user timeout") && a.Retransmissions < 8, "User timeout not enforced");
            var m = new Network(settingsB: new TcpSettings { AcceptPeerUserTimeout = true }); var (c, d) = m.Connect();
            c.UserTimeout = TimeSpan.FromMinutes(5); c.Send("x"u8); m.Pump();
            Check(d.UserTimeout == TimeSpan.FromMinutes(5), "Peer did not adopt the advertised user timeout");
        });
        test("urgent send marks the end of urgent data and delivers it inline", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var start = b.NextReceiveSequence;
            a.Send("abc"u8); a.SendUrgent("!!"u8); n.Pump(); n.AdvanceMilliseconds(200);
            Check(b.UrgentDataEnd == start + 5 && ReadAll(b).SequenceEqual([.. "abc!!"u8]), "Urgent pointer or data wrong");
        });
        test("closing the read side with unread or later data resets the connection", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send("unread"u8); n.Pump();
            b.CloseRead(); n.Pump();
            Check(b.State == TcpState.Closed && b.FailureReason!.Contains("discarded") && a.State == TcpState.Closed && a.FailureReason == "Connection reset by peer.",
                "Unread data not signalled with RST");
            var m = new Network(); var (c, d) = m.Connect(); d.CloseRead(); d.Send("still writable"u8); m.Pump();
            Check(d.State == TcpState.Established && ReadAll(c).Length == 14, "Read-side shutdown broke writing");
            c.Send("late"u8); m.Pump(); Check(d.State == TcpState.Closed && c.State == TcpState.Closed, "Late data after read shutdown not reset");
        });
        test("data carried on a SYN is queued and delivered once the handshake completes", () =>
        {
            var n = new Network(); TcpConnection? server = null; n.TcpB.Listen(80, c => server = c);
            var syn = new TcpSegment(5000, 80, 1000, 0, TcpFlags.Syn, 65535, "hello"u8.ToArray());
            Inject(n, n.B, syn);
            var synAck = Parse(n.Queue.Dequeue().Packet);
            Check(synAck.AcknowledgmentNumber == 1006 && server is null, "SYN data not acknowledged or delivered early");
            Inject(n, n.B, new TcpSegment(5000, 80, 1006, synAck.SequenceNumber + 1, TcpFlags.Ack, 65535, default));
            Check(server?.State == TcpState.Established && ReadAll(server).SequenceEqual([.. "hello"u8]), "SYN data lost");
        });
        test("Fast Open fetches a cookie, then carries data on the SYN for a one-way-trip request", () =>
        {
            var n = new Network(); var requests = new List<string>(); var states = new List<TcpState>();
            n.TcpB.Listen(80, c =>
            {
                states.Add(c.State);
                void Serve(TcpConnection s) { var text = System.Text.Encoding.ASCII.GetString(ReadAll(s)); if (text.Length == 0) return; requests.Add(text); s.Send("ok"u8); }
                c.DataAvailable += Serve; Serve(c);
            });
            var first = n.TcpA.Connect(n.B.LocalAddress, 80, initialData: "GET /1"u8);
            var firstSyn = Parse(n.Queue.Peek().Packet);
            Check(firstSyn.Payload.IsEmpty && firstSyn.ReadOptions().FastOpenCookie is { Length: 0 }, "First SYN did not request a cookie");
            n.Pump(); n.AdvanceMilliseconds(200);
            Check(requests.SequenceEqual(["GET /1"]) && !first.FastOpenUsed, "Cookie-fetch connection failed");
            var second = n.TcpA.Connect(n.B.LocalAddress, 80, initialData: "GET /2"u8);
            Check(Parse(n.Queue.Peek().Packet).Payload.Span.SequenceEqual("GET /2"u8), "Cached cookie not used for SYN data");
            n.DeliverNext();
            Check(requests.Count == 2 && requests[1] == "GET /2" && states[1] == TcpState.SynReceived, "Server did not accept SYN data immediately");
            n.Pump(); n.AdvanceMilliseconds(200);
            Check(second.FastOpenUsed && second.State == TcpState.Established && ReadAll(second).SequenceEqual([
                .. "ok"u8
            ]), "Fast Open response lost");
            var forged = new TcpOptionWriter(); forged.TryAdd(TcpOptionWriter.FastOpen([9, 9, 9, 9, 9, 9, 9, 9]));
            Inject(n, n.B, new TcpSegment(5001, 80, 7000, 0, TcpFlags.Syn, 65535, "evil"u8.ToArray(), forged.ToArray()));
            var reply = Parse(n.Queue.Dequeue().Packet);
            Check(reply.AcknowledgmentNumber == 7001 && reply.ReadOptions().FastOpenCookie is { Length: 8 } && requests.Count == 2, "Forged cookie data accepted");
        });
        test("a new SYN may replace a TIME-WAIT connection on the same four-tuple", () =>
        {
            var n = new Network(); TcpConnection? server = null; n.TcpB.Listen(80, c => server = c);
            var a = n.TcpA.Connect(n.B.LocalAddress, 80, 40000); n.Pump();
            var old = server!; old.Close(); n.Pump(); a.Close(); n.Pump();
            Check(old.State == TcpState.TimeWait && a.State == TcpState.Closed, "Server did not reach TIME-WAIT");
            n.Clock.Advance(TimeSpan.FromSeconds(1));
            var again = n.TcpA.Connect(n.B.LocalAddress, 80, 40000); n.Pump();
            Check(again.State == TcpState.Established && old.State == TcpState.Closed && old.FailureReason is null &&
                  server != old && server.State == TcpState.Established && n.TcpB.Connections.Count == 1, "TIME-WAIT blocked a valid new SYN");
        });
        test("a lowered path MTU is raised again after ten minutes", () =>
        {
            var n = new Network(); var (a, _) = n.Connect(); a.Send(new byte[2000]);
            var original = n.Queue.Dequeue().Packet; n.Queue.Clear();
            var error = new IcmpPacket(3, 4, 600, original.Serialize()[..28]);
            n.A.Receive(new IPv4Packet(0, 123, 0, 64, 1, n.B.LocalAddress, n.A.LocalAddress, default, error.Serialize()).Serialize(), false);
            Check(a.MaximumSegmentSize == 548, "Path MTU not lowered"); n.Pump();
            n.Advance(599); Check(a.MaximumSegmentSize == 548, "Path MTU raised early");
            n.Advance(1); Check(a.MaximumSegmentSize == 1448, "Path MTU never raised");
        });
        test("black-hole detection shrinks segments when large packets vanish without ICMP", () =>
        {
            var n = new Network(); var (a, b) = n.Connect();
            n.Filter = (_, packet) => packet.TotalLength > 600 ? null : packet;
            var data = new byte[20000]; Random.Shared.NextBytes(data); a.Send(data);
            var received = new List<byte>();
            for (var i = 0; i < 120 && received.Count < data.Length; i++) { n.Advance(1); received.AddRange(ReadAll(b)); }
            Check(received.SequenceEqual(data) && a.MaximumSegmentSize <= 600 - 52, "Black hole not detected");
        });
        test("SACK repairs two holes in one round trip without a timeout", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect(); var data = new byte[10 * a.MaximumSegmentSize]; Random.Shared.NextBytes(data);
            a.Send(data); var sent = n.Queue.ToArray(); n.Queue.Clear();
            for (var i = 0; i < sent.Length; i++) if (i is not (1 or 4)) n.Queue.Enqueue(sent[i]);
            n.Pump();
            Check(ReadAll(b).SequenceEqual(data) && a.Retransmissions == 2, $"SACK recovery failed or resent too much: {b.Available} {a.Retransmissions} {sent.Length}");
            Check(n.History.Where(p => p.SourceAddress.Equals(n.B.LocalAddress)).Any(p => Parse(p).ReadOptions().SackBlocks.Count == 2), "Receiver never reported both holes");
            n.AdvanceMilliseconds(200); n.History.Clear(); a.Send("dup"u8); var copy = n.Queue.Peek(); n.Pump(); n.Queue.Enqueue(copy); n.Pump();
            var dsack = n.History.Where(p => p.SourceAddress.Equals(n.B.LocalAddress)).Select(Parse).Last();
            var blocks = dsack.ReadOptions().SackBlocks;
            Check(blocks.Count == 1 && blocks[0].End.Value <= dsack.AcknowledgmentNumber, "Duplicate not reported as D-SACK");
        });
        test("tail loss probe repairs a lost final segment well before the RTO", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var data = new byte[3 * a.MaximumSegmentSize];
            a.Send(data); var sent = n.Queue.ToArray(); n.Queue.Clear();
            n.Queue.Enqueue(sent[0]); n.Queue.Enqueue(sent[1]); n.Pump();
            var start = n.Clock.GetUtcNow();
            while (b.Available < data.Length && n.Clock.GetUtcNow() - start < TimeSpan.FromSeconds(2)) n.AdvanceMilliseconds(20);
            Check(b.Available == data.Length && n.Clock.GetUtcNow() - start < TimeSpan.FromMilliseconds(500) && a.RetransmissionTimeoutSeconds == 1,
                $"Tail loss waited for the retransmission timeout: {b.Available}/{data.Length} {(n.Clock.GetUtcNow() - start).TotalMilliseconds} {a.RetransmissionTimeoutSeconds} {a.Retransmissions}");
        });
        test("ECN marks reduce the window once per round trip without retransmission", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var marked = 0;
            n.Filter = (fromA, packet) => fromA && (packet.TypeOfService & 3) == 2 && marked++ < 3 ? packet with { TypeOfService = 3 } : packet;
            var data = new byte[200_000]; a.Send(data);
            for (var i = 0; i < 100 && b.Available < data.Length; i++) { n.Pump(); n.AdvanceMilliseconds(50); if (i % 5 == 4) ReadAll(b); }
            var fromA = n.History.Where(p => p.SourceAddress.Equals(n.A.LocalAddress)).ToArray();
            Check(marked > 0 && a.Retransmissions == 0 && a.SlowStartThreshold < int.MaxValue, "ECN mark not treated as congestion");
            Check(fromA.Where(p => Parse(p).Payload.Length > 0).All(p => (p.TypeOfService & 3) == 2), "Data not sent ECN-capable");
            Check(fromA.Select(Parse).Count(s => s.Has(TcpFlags.Cwr) && !s.Has(TcpFlags.Syn)) == 1, "CWR not sent exactly once for one round trip of marks");
            Check(n.History.Where(p => p.SourceAddress.Equals(n.B.LocalAddress)).Any(p => Parse(p).Has(TcpFlags.Ece)), "Receiver did not echo congestion");
        });
        test("CUBIC and NewReno windows follow their RFC reduction and growth rules", () =>
        {
            Check(CongestionController.InitialWindow(1460, 10) == 14600 && CongestionController.InitialWindow(536, 10) == 5360 &&
                  CongestionController.InitialWindow(9000, 10) == 18000, "RFC 6928 initial window wrong");
            var now = DateTimeOffset.UnixEpoch; var rtt = TimeSpan.FromMilliseconds(100);
            var cubic = CongestionController.Create(TcpCongestionAlgorithm.Cubic); var reno = CongestionController.Create(TcpCongestionAlgorithm.NewReno);
            foreach (var controller in new[] { cubic, reno }) { controller.Start(1000, 100); controller.OnCongestionEvent(100_000, 1000, now); }
            Check(cubic.Window == 70_000 && reno.Window == 50_000, "Multiplicative decrease wrong");
            Check(cubic.UndoReduction() && cubic.Window == 100_000 && !cubic.UndoReduction(), "Spurious reduction not undone once");
            cubic.OnCongestionEvent(100_000, 1000, now);
            for (var t = 0; t < 40; t++)
            {
                now += rtt;
                foreach (var controller in new[] { cubic, reno })
                    for (var ack = 0; ack < (int)(controller.Window / 1000); ack++) controller.OnAcknowledged(1000, 1000, now, rtt);
            }
            // K = cbrt((100 - 70) / 0.4) = 4.2 s, so CUBIC is back at W_max while Reno has regained only a third of its cut.
            Check(cubic.Window >= 99_000 && cubic.Window > reno.Window + 5_000 && reno.Window > 85_000, $"Growth after 4 s wrong: CUBIC {cubic.Window}, Reno {reno.Window}");
        });
        test("the initial window is ten segments and shrinks back after an idle period", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.NoDelay = true;
            a.Send(new byte[100_000]); Check(n.Queue.Count == 10, "Initial window not ten segments");
            for (var i = 0; i < 50 && a.BufferedSendBytes > 0; i++) { n.Pump(); ReadAll(b); n.AdvanceMilliseconds(200); }
            Check(a.CongestionWindow > 14480, "Window did not grow");
            n.Advance(3); a.Send([1]);
            Check(a.CongestionWindow <= CongestionController.InitialWindow(a.MaximumSegmentSize, 10), "Idle restart did not shrink the window");
        });
        test("limited transmit sends new data on the first two duplicate ACKs without SACK", () =>
        {
            var n = new Network(600, Plain); var (a, _) = n.Connect(); a.NoDelay = true;
            a.Send(new byte[20 * a.MaximumSegmentSize]); var sent = n.Queue.ToArray(); n.Queue.Clear();
            n.B.Receive(sent[1].Packet.Serialize(), false); n.B.Receive(sent[2].Packet.Serialize(), false);
            var duplicates = n.Queue.ToArray(); n.Queue.Clear();
            Check(duplicates.Length == 2, "Receiver did not send two duplicate ACKs");
            foreach (var ack in duplicates) n.A.Receive(ack.Packet.Serialize(), false);
            Check(n.Queue.Count == 2 && n.Queue.All(p => Parse(p.Packet).Payload.Length > 0) && a.Retransmissions == 0, "Limited transmit did not send two new segments");
        });
        test("SYN cookies complete handshakes beyond the backlog and keep negotiated options", () =>
        {
            var n = new Network(); var accepted = new List<TcpConnection>(); n.TcpB.Listen(80, accepted.Add, backlog: 1);
            n.TcpA.Connect(n.B.LocalAddress, 80); n.DeliverNext(); n.Queue.Clear();
            var second = n.TcpA.Connect(n.B.LocalAddress, 80); n.Pump();
            var server = accepted.Single();
            Check(second.State == TcpState.Established && server.State == TcpState.Established, "Cookie handshake failed");
            Check(server.TimestampsEnabled && server.WindowScalingEnabled && server.SelectiveAcknowledgmentsEnabled && server.ExplicitCongestionNotificationEnabled,
                "Cookie lost negotiated options");
            second.Send("via cookie"u8); n.Pump(); n.AdvanceMilliseconds(200);
            Check(ReadAll(server).SequenceEqual([.. "via cookie"u8]) && second.BufferedSendBytes == 0, "Cookie connection cannot carry data");
            Inject(n, n.B, new TcpSegment(6000, 80, 1234, 5678, TcpFlags.Ack, 65535, default));
            Check(Parse(n.Queue.Dequeue().Packet).Has(TcpFlags.Rst), "Forged cookie ACK not reset");
        });
        test("TCP-AO and MD5 sign every segment and drop forged ones", () =>
        {
            foreach (var algorithm in new[] { TcpAuthenticationAlgorithm.HmacSha1, TcpAuthenticationAlgorithm.AesCmac128, TcpAuthenticationAlgorithm.Md5 })
            {
                var n = new Network(); var secret = "correct horse battery"u8.ToArray();
                n.TcpA.AddAuthenticationKey(new TcpAuthenticationKey(n.B.LocalAddress, secret, algorithm, SendId: 1, ReceiveId: 2));
                n.TcpB.AddAuthenticationKey(new TcpAuthenticationKey(n.A.LocalAddress, secret, algorithm, SendId: 2, ReceiveId: 1));
                var (a, b) = n.Connect(); a.Send("signed"u8); n.Pump(); n.AdvanceMilliseconds(200);
                Check(a.Authenticated && ReadAll(b).SequenceEqual([.. "signed"u8]), $"{algorithm} connection failed");
                Check(n.History.Select(Parse).All(s => algorithm == TcpAuthenticationAlgorithm.Md5 ? s.ReadOptions().Md5DigestOffset is not null : s.ReadOptions().Authentication is not null),
                    $"{algorithm} left a segment unsigned");
                a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, a.NextSendSequence, TcpFlags.Rst, 0, default));
                Inject(n, n.A, new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, a.NextSendSequence, TcpFlags.Ack, 65535, "forged"u8.ToArray()));
                Check(a.State == TcpState.Established && a.Available == 0, $"{algorithm} accepted a forged segment");
                var tampered = false;
                n.Filter = (_, packet) =>
                {
                    if (tampered || Parse(packet).Payload.IsEmpty) return packet;
                    tampered = true; var payload = packet.Payload.ToArray(); payload[^1] ^= 1;
                    var bad = TcpSegment.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span) with { Payload = payload[^6..] };
                    return packet with { Payload = bad.Serialize(packet.SourceAddress, packet.DestinationAddress) };
                };
                b.Send("reply"u8); n.Pump(); Check(a.Available == 0, $"{algorithm} accepted tampered data");
                n.Filter = null; n.Advance(1); n.AdvanceMilliseconds(200);
                Check(ReadAll(a).SequenceEqual([.. "reply"u8]), $"{algorithm} did not recover from the tampered segment");
            }
            var m = new Network();
            m.TcpA.AddAuthenticationKey(new TcpAuthenticationKey(m.B.LocalAddress, [.. "one"u8]));
            m.TcpB.AddAuthenticationKey(new TcpAuthenticationKey(m.A.LocalAddress, [.. "two"u8]));
            m.TcpB.Listen(80, _ => { }); var c = m.TcpA.Connect(m.B.LocalAddress, 80); m.Pump();
            Check(c.State == TcpState.SynSent && m.TcpB.Connections.Count == 0, "Mismatched keys established a connection");
        });
        test("TCP-AO follows the peer's RNextKeyID to roll keys and can exclude other options", () =>
        {
            var n = new Network(); var one = "first key"u8.ToArray(); var two = "second key"u8.ToArray();
            n.TcpA.AddAuthenticationKey(new TcpAuthenticationKey(n.B.LocalAddress, one, SendId: 1, ReceiveId: 1));
            n.TcpA.AddAuthenticationKey(new TcpAuthenticationKey(n.B.LocalAddress, two, SendId: 2, ReceiveId: 2));
            n.TcpB.AddAuthenticationKey(new TcpAuthenticationKey(n.A.LocalAddress, two, SendId: 2, ReceiveId: 2));
            n.TcpB.AddAuthenticationKey(new TcpAuthenticationKey(n.A.LocalAddress, one, SendId: 1, ReceiveId: 1));
            var (a, b) = n.Connect(); n.History.Clear(); a.Send("rolled"u8); n.Pump(); n.AdvanceMilliseconds(200);
            Check(ReadAll(b).SequenceEqual([.. "rolled"u8]) &&
                  n.History.Where(p => p.SourceAddress.Equals(n.A.LocalAddress)).All(p => Parse(p).ReadOptions().Authentication!.Value.KeyId == 2),
                "Sender did not switch to the key the peer asked for");
            var m = new Network(); var secret = "options excluded"u8.ToArray();
            m.TcpA.AddAuthenticationKey(new TcpAuthenticationKey(m.B.LocalAddress, secret, TcpAuthenticationAlgorithm.AesCmac128) { IncludeOptions = false });
            m.TcpB.AddAuthenticationKey(new TcpAuthenticationKey(m.A.LocalAddress, secret, TcpAuthenticationAlgorithm.AesCmac128) { IncludeOptions = false });
            var (c, d) = m.Connect(); c.Send("ok"u8); m.Pump(); m.AdvanceMilliseconds(200);
            Check(ReadAll(d).SequenceEqual([.. "ok"u8]), "TCP-AO without options failed");
        });
        test("a lost SYN is resent without its ECN request and Fast Open data", () =>
        {
            var n = new Network(); var requests = new List<byte>(); n.TcpB.Listen(80, c => { c.DataAvailable += s => requests.AddRange(ReadAll(s)); requests.AddRange(ReadAll(c)); });
            n.TcpA.Connect(n.B.LocalAddress, 80, initialData: "prime"u8); n.Pump(); n.AdvanceMilliseconds(200);
            requests.Clear();
            var a = n.TcpA.Connect(n.B.LocalAddress, 80, initialData: "retry me"u8);
            var first = Parse(n.Queue.Dequeue().Packet);
            Check(first.Has(TcpFlags.Ece) && first.Has(TcpFlags.Cwr) && first.Payload.Length == 8, "First SYN lacked ECN request or Fast Open data");
            n.Clock.Advance(TimeSpan.FromSeconds(1)); n.A.Tick();
            var retry = Parse(n.Queue.Peek().Packet);
            Check(retry.Has(TcpFlags.Syn) && !retry.Has(TcpFlags.Ece) && retry.Payload.IsEmpty, "Retransmitted SYN not simplified");
            n.Pump(); n.AdvanceMilliseconds(200);
            Check(a.State == TcpState.Established && !a.ExplicitCongestionNotificationEnabled && !a.FastOpenUsed &&
                  requests.SequenceEqual([.. "retry me"u8]), "Data after the plain SYN was lost");
        });
        test("PAWS drops a segment whose timestamp predates TS.Recent", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); b.Send("x"u8); n.Pump();
            var recent = n.History.Where(p => p.SourceAddress.Equals(n.B.LocalAddress)).Select(Parse).Last().ReadOptions().Timestamp!.Value.Value;
            ReadAll(a); n.Queue.Clear();
            TcpSegment Data(uint tsval) { var w = new TcpOptionWriter(); w.TryAdd(TcpOptionWriter.Timestamp(new TcpTimestamp(tsval, 0))); return new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, a.NextSendSequence, TcpFlags.Ack, 65535, "y"u8.ToArray(), w.ToArray()); }
            a.Receive(Data(recent - 1000));
            Check(a.Available == 0 && n.Queue.Count == 1, "Old-timestamp segment accepted");
            a.Receive(Data(recent + 1)); Check(a.Available == 1, "Fresh-timestamp segment rejected");
        });
        test("timestamps expose a spurious retransmission timeout and undo it", () =>
        {
            var n = new Network(); var (a, _) = n.Connect(); a.Send(new byte[4 * a.MaximumSegmentSize]); n.Pump(); n.AdvanceMilliseconds(200);
            var before = a.CongestionWindow; a.Send("late"u8);
            n.DeliverNext(); // Data reaches the peer, whose ACK is delayed past our RTO.
            n.Clock.Advance(TimeSpan.FromMilliseconds(1100)); n.B.Tick(); n.A.Tick();
            Check(a.Retransmissions == 1 && a.CongestionWindow < before, "Timeout did not fire");
            n.DeliverNext();
            Check(a.SpuriousRetransmissionTimeouts == 1 && a.CongestionWindow >= before, "Spurious timeout not undone");
            n.Pump(); Check(a.BufferedSendBytes == 0, "Connection disturbed by spurious timeout");
        });
    }

    private static TcpSegment Parse(IPv4Packet packet) => TcpSegment.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span);

    private static int AcksFrom(Network n, IPv4Host host) => n.History.Count(p => p.SourceAddress.Equals(host.LocalAddress));

    /// <summary>Delivers a hand-built segment to <paramref name="to"/> as if from the other host.</summary>
    private static void Inject(Network n, IPv4Host to, TcpSegment segment)
    {
        var from = to == n.A ? n.B.LocalAddress : n.A.LocalAddress;
        to.Receive(new IPv4Packet(0, 1, 0, 64, 6, from, to.LocalAddress, default, segment.Serialize(from, to.LocalAddress)).Serialize(), false);
    }
}
