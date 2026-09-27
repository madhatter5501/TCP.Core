using System.Net;
using TCP.L3.Network;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.L4.Transport.Tcp;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.Tests;

internal static partial class TcpTests
{
    public static int Run()
    {
        var passed = 0;
        Test("codec matches an independent checksum fixture and rejects corruption", () =>
        {
            var a = IPAddress.Parse("192.0.2.1"); var b = IPAddress.Parse("192.0.2.2");
            var fixture = Convert.FromHexString("3039005001020304000000005018ffff32d40000616263");
            var segment = new TcpSegment(12345, 80, 0x01020304, 0, TcpFlags.Ack | TcpFlags.Psh, 65535, "abc"u8.ToArray());
            Check(segment.Serialize(a, b).SequenceEqual(fixture), "Checksum fixture mismatch");
            Check(TcpSegment.Parse(a, b, fixture).Payload.Span.SequenceEqual("abc"u8), "Payload parse mismatch");
            fixture[^1] ^= 1; Throws(() => TcpSegment.Parse(a, b, fixture));
            Throws(() => (segment with { Options = new byte[] { 2, 3, 0, 0 } }).Serialize(a, b));
            Throws(() => TcpSegment.Parse(a, b, new byte[19]));
            Throws(() => TcpSegment.Parse(b, a, segment.Serialize(a, IPAddress.Parse("192.0.2.3"))));
        });
        Test("three-way handshake negotiates MSS and sends an ordered full-duplex stream", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect();
            // 600 - 40 header bytes, less 12 for the timestamp option every segment carries.
            Check(a.MaximumSegmentSize == 548 && b.MaximumSegmentSize == 548 && a.TimestampsEnabled, "MSS not negotiated");
            var data = Enumerable.Range(0, 8000).Select(i => (byte)i).ToArray();
            Check(a.Send(data) == data.Length && b.Send("reply"u8) == 5, "Send count wrong"); n.Pump();
            Check(ReadAll(b).SequenceEqual(data) && ReadAll(a).SequenceEqual([.. "reply"u8]), "Stream mismatch");
            n.Pump(); Check(a.BufferedSendBytes == 0, "ACK did not drain flight");
            Check(n.History.All(p => p.TotalLength <= 600), "Oversized IP packet");
        });
        Test("lost SYN and lost final handshake ACK recover without duplicate accept", () =>
        {
            var n = new Network(); var accepted = 0;
            n.TcpB.Listen(80, _ => accepted++);
            var a = n.TcpA.Connect(n.B.LocalAddress, 80);
            n.Queue.Clear(); n.Clock.Advance(TimeSpan.FromSeconds(1)); n.A.Tick(); // Drop initial SYN.
            n.DeliverNext(); n.DeliverNext(); // SYN -> SYN-ACK -> final ACK queued.
            n.Queue.Clear(); n.Advance(3);
            Check(a.State == TcpState.Established && accepted == 1, "Handshake recovery failed");
        });
        Test("out-of-order and duplicate data deliver once with cumulative ACKs", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect(); var data = new byte[1600]; Random.Shared.NextBytes(data);
            a.Send(data); var packets = n.Queue.ToArray(); n.Queue.Clear();
            foreach (var packet in packets.Reverse()) { n.Queue.Enqueue(packet); n.Queue.Enqueue(packet); }
            n.Pump(); Check(ReadAll(b).SequenceEqual(data), "Reorder or duplicate delivery failure");
            n.Pump(); Check(a.BufferedSendBytes == 0, "Cumulative ACK failed");
        });
        Test("data timeout retransmits lost bytes and applies Karn backoff", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send("lost"u8); n.Queue.Clear();
            n.Advance(1); Check(ReadAll(b).SequenceEqual([.. "lost"u8]), "Retransmission failed");
            Check(a.Retransmissions > 0 && a.RetransmissionTimeoutSeconds >= 2, "Backoff/sample handling failed");
        });
        Test("Reno fast retransmit recovers a gap before the timer fires", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect();
            a.Send(new byte[10000]); n.Pump(); ReadAll(b); n.Pump();
            a.Send(new byte[8000]); n.Queue.Dequeue(); n.Pump();
            Check(a.Retransmissions > 0 && b.Available == 8000, "Fast retransmit did not recover gap");
        });
        Test("burst loss of consecutive segments recovers in a few RTOs, not one RTO per segment", () =>
        {
            // Regression: after a timeout only the first lost segment was resent, so each further
            // lost segment waited a doubling RTO (six losses took about 63 s).
            var n = new Network(600); var (a, b) = n.Connect(); var data = new byte[20000]; Random.Shared.NextBytes(data);
            var received = new List<byte>(); b.DataAvailable += c => received.AddRange(ReadAll(c));
            var dataSegments = 0; var start = n.Clock.GetUtcNow();
            a.Send(data);
            while (received.Count < data.Length && n.Clock.GetUtcNow() - start < TimeSpan.FromMinutes(5))
            {
                while (n.Queue.TryDequeue(out var item))
                {
                    var isData = item.FromA && item.Packet.Payload.Length > TcpWireFormat.MinimumHeaderLength;
                    if (isData && ++dataSegments is >= 4 and < 10) continue; // Drop six consecutive data segments once.
                    (item.FromA ? n.B : n.A).Receive(item.Packet.Serialize(), false);
                }
                n.Clock.Advance(TimeSpan.FromMilliseconds(100)); n.A.Tick(); n.B.Tick();
            }
            var elapsed = n.Clock.GetUtcNow() - start;
            Check(received.SequenceEqual(data), "Burst loss corrupted or truncated the stream");
            Check(elapsed < TimeSpan.FromSeconds(10), $"Burst loss recovery took {elapsed.TotalSeconds:F1} s");
        });
        Test("slow byte-at-a-time reader does not cause silly-window tiny segments", () =>
        {
            // RFC 1122 4.2.3.3/4.2.3.4: the receiver must not advertise, and the sender must not fill,
            // tiny window openings; full-size segments should resume once enough space frees.
            var n = new Network(); var (a, b) = n.Connect(capacity: 4096);
            a.Send(new byte[20000]); n.Pump(); Check(b.ReceiveWindow == 0, "Receiver window did not fill");
            n.History.Clear(); var one = new byte[1];
            for (var i = 0; i < 4000; i++) { b.Read(one); n.Pump(); }
            var mss = a.MaximumSegmentSize;
            var tiny = n.History.Count(p => p.SourceAddress.Equals(n.A.LocalAddress) &&
                p.Payload.Length - TcpWireFormat.MinimumHeaderLength is > 0 and var data && data < mss);
            var updates = n.History.Count(p => p.SourceAddress.Equals(n.B.LocalAddress));
            Check(tiny == 0, $"Sender emitted {tiny} sub-MSS segments into a slowly opening window");
            Check(updates < 20, $"Receiver sent {updates} window updates for 4000 one-byte reads");
        });
        Test("receive window and persist recover a lost window update", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(capacity: 8); var sent = Enumerable.Range(0, 23).Select(i => (byte)i).ToArray();
            a.Send(sent); n.Pump(); Check(b.Available == 8 && b.ReceiveWindow == 0, "Receive buffer overflow");
            var got = new List<byte>(); got.AddRange(ReadAll(b)); n.Queue.Clear(); // Lost window-update ACK.
            for (var i = 0; i < 15; i++) { n.Advance(2); got.AddRange(ReadAll(b)); n.Pump(); }
            Check(got.SequenceEqual(sent) && a.BufferedSendBytes == 0, "Persist recovery lost bytes");
        });
        Test("half-close allows a final response and reaches TIME-WAIT then CLOSED", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send("request"u8); a.Close(); n.Pump();
            Check(b.PeerClosed && b.State == TcpState.CloseWait && a.State == TcpState.FinWait2, "Half-close state failure");
            b.Send("last response"u8); b.Close(); n.Pump();
            Check(ReadAll(a).SequenceEqual([.. "last response"u8]) && a.State == TcpState.TimeWait && b.State == TcpState.Closed, "Final response failed");
            n.Advance(240); Check(a.State == TcpState.Closed && n.TcpA.Connections.Count == 0, "TIME-WAIT did not expire");
        });
        Test("simultaneous open and simultaneous close", () =>
        {
            var n = new Network(); var a = n.TcpA.Connect(n.B.LocalAddress, 2000, 1000); var b = n.TcpB.Connect(n.A.LocalAddress, 1000, 2000);
            n.Pump(); Check(a.State == TcpState.Established && b.State == TcpState.Established, "Simultaneous open failed");
            a.Close(); b.Close(); n.Pump(); Check(a.State == TcpState.TimeWait && b.State == TcpState.TimeWait, "Simultaneous close failed");
        });
        Test("closed ports refuse and valid resets abort while off-sequence resets do not", () =>
        {
            var n = new Network(); var refused = n.TcpA.Connect(n.B.LocalAddress, 9); n.Pump();
            Check(refused.State == TcpState.Closed && refused.FailureReason == "Connection refused.", "Closed port was not refused");
            var (a, b) = n.Connect();
            a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence + 1, a.NextSendSequence, TcpFlags.Rst, 0, default));
            Check(a.State == TcpState.Established, "In-window nonexact RST killed connection");
            b.Abort(); n.Pump(); Check(a.State == TcpState.Closed, "RST did not abort");
        });
        Test("invalid future ACK cannot inject data or acknowledge unsent bytes", () =>
        {
            var n = new Network(); var (a, b) = n.Connect();
            a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, unchecked(a.NextSendSequence + 100), TcpFlags.Ack, 65535, "bad"u8.ToArray()));
            Check(a.Available == 0 && a.State == TcpState.Established, "Future ACK accepted");
        });
        Test("sequence arithmetic crosses uint wrap for both streams and FIN", () =>
        {
            var n = new Network();
            var a = new TcpConnection(n.TcpA, 1000, n.B.LocalAddress, 2000, uint.MaxValue - 2, 65535, null);
            a.Open();
            a.Receive(new TcpSegment(2000, 1000, uint.MaxValue - 1, uint.MaxValue - 1, TcpFlags.Syn | TcpFlags.Ack, 65535, default));
            a.Send(new byte[8]); Check(a.NextSendSequence == 6, "Send sequence did not wrap");
            a.Receive(new TcpSegment(2000, 1000, uint.MaxValue, 6, TcpFlags.Ack, 65535, new byte[] { 1, 2, 3 }));
            Check(a.NextReceiveSequence == 2 && a.Available == 3 && a.BufferedSendBytes == 0, "Receive/ACK wrap failed");
            a.Close(); a.Receive(new TcpSegment(2000, 1000, 2, 7, TcpFlags.Ack | TcpFlags.Fin, 65535, default));
            Check(a.State == TcpState.TimeWait, "FIN wrap failed");
        });
        Test("partial ACK trims flight and retransmits only the remaining suffix", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var start = a.NextSendSequence; a.Send("abcdefgh"u8); n.Queue.Clear();
            a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, start + 3, TcpFlags.Ack, 65535, default));
            n.Clock.Advance(TimeSpan.FromSeconds(1)); n.A.Tick();
            var retransmission = TcpSegment.Parse(n.A.LocalAddress, n.B.LocalAddress, n.Queue.Last().Packet.Payload.Span);
            Check(retransmission.SequenceNumber == start + 3 && retransmission.Payload.Span.SequenceEqual("defgh"u8), "Partial ACK trimming failed");
        });
        Test("malformed checksum is discarded and retransmission recovers", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send("integrity"u8);
            var item = n.Queue.Dequeue(); var corrupted = item.Packet.Payload.ToArray(); corrupted[^1] ^= 1;
            n.B.Receive((item.Packet with { Payload = corrupted }).Serialize(), false);
            Check(b.Available == 0, "Invalid checksum delivered"); n.Advance(1); Check(b.Available == 9, "Valid retry not delivered");
        });
        Test("backlog, listener disposal and send buffer are bounded", () =>
        {
            var n = new Network(); using var listener = n.TcpB.Listen(80, _ => { }, backlog: 1);
            n.TcpA.Connect(n.B.LocalAddress, 80); n.DeliverNext();
            n.TcpA.Connect(n.B.LocalAddress, 80); var last = n.Queue.Last(); n.Queue.Clear(); n.B.Receive(last.Packet.Serialize(), false);
            Check(n.TcpB.Connections.Count == 1, "Backlog exceeded"); listener.Dispose(); Check(n.TcpB.Connections.Count == 0, "Half-open survived listener disposal");
            var m = new Network(); var (a, _) = m.Connect();
            Check(a.Send(new byte[TcpConnection.MaximumSendBuffer + 1]) == TcpConnection.MaximumSendBuffer && a.Send([1]) == 0, "Send buffer unbounded");
        });
        Test("Nagle batches small writes until previous data is acknowledged", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send([1]); a.Send([2]);
            Check(n.Queue.Count == 1, "Nagle did not defer second write");
            n.Pump(); n.AdvanceMilliseconds(200); // The receiver's delayed ACK releases the held byte.
            Check(ReadAll(b).SequenceEqual(new byte[] { 1, 2 }), "Nagle lost data");
        });
        Test("lost FIN and lost FIN ACK recover without duplicate EOF", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var eof = 0; b.ReadClosed += _ => eof++;
            a.Close(); n.Queue.Clear(); n.Advance(1); Check(eof == 1, "Lost FIN not recovered");
            b.Close(); n.DeliverNext(); n.Queue.Clear(); n.Advance(2);
            Check(b.State == TcpState.Closed && a.State == TcpState.TimeWait && eof == 1, "Lost final ACK not recovered");
        });
        Test("retransmission exhaustion removes a dead connection", () =>
        {
            var n = new Network(); var a = n.TcpA.Connect(n.B.LocalAddress, 80);
            for (var i = 0; i < 12; i++) { n.Queue.Clear(); n.Clock.Advance(TimeSpan.FromSeconds(60)); n.A.Tick(); }
            Check(a.State == TcpState.Closed && a.FailureReason!.Contains("retransmission"), "Dead connection retained");
        });
        Test("validated ICMP fragmentation-needed reduces segment size and recovers", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Send(new byte[2000]);
            var original = n.Queue.Dequeue().Packet; n.Queue.Clear();
            var quote = original.Serialize()[..28];
            var error = new TCP.L3.Network.Icmp.IcmpPacket(3, 4, 600, quote);
            var packet = new IPv4Packet(0, 123, 0, 64, 1, n.B.LocalAddress, n.A.LocalAddress, default, error.Serialize());
            n.A.Receive(packet.Serialize(), false);
            Check(a.MaximumSegmentSize == 548, "ICMP did not update path MTU");
            Check(n.Queue.All(item => item.Packet.TotalLength <= 600), "Retransmit did not split the old flight");
            for (var i = 0; i < 10 && b.Available < 2000; i++) n.Advance(2);
            Check(b.Available == 2000, "Path-MTU recovery lost data");
        });
        Test("urgent pointer is exposed while urgent bytes remain in the stream", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); var notifications = 0; a.UrgentDataAvailable += _ => notifications++;
            var sequence = a.NextReceiveSequence;
            a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, sequence, a.NextSendSequence, TcpFlags.Ack | TcpFlags.Urg, 65535, "abc"u8.ToArray(), UrgentPointer: 3));
            Check(a.UrgentDataEnd == sequence + 3 && notifications == 1 && ReadAll(a).SequenceEqual([.. "abc"u8]), "Urgent indication failed");
        });
        Test("bidirectional transfer survives seeded loss, duplication and reordering", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect(); var random = new Random(20260927);
            var left = new byte[12000]; var right = new byte[9000]; random.NextBytes(left); random.NextBytes(right);
            a.Send(left); b.Send(right); a.Close(); b.Close();
            for (var tick = 0; tick < 600 && !(a.PeerClosed && b.PeerClosed && a.BufferedSendBytes == 0 && b.BufferedSendBytes == 0); tick++)
            {
                var steps = 0;
                while (n.Queue.Count > 0)
                {
                    if (++steps > 10000) throw new Exception("Packet exchange did not quiesce");
                    var batch = n.Queue.OrderBy(_ => random.Next()).ToArray(); n.Queue.Clear();
                    foreach (var item in batch)
                    {
                        if (random.NextDouble() < .15) continue;
                        var receiver = item.FromA ? n.B : n.A;
                        receiver.Receive(item.Packet.Serialize(), false);
                        if (random.NextDouble() < .1) receiver.Receive(item.Packet.Serialize(), false);
                    }
                }
                n.Clock.Advance(TimeSpan.FromSeconds(1)); n.A.Tick(); n.B.Tick();
            }
            Check(ReadAll(a).SequenceEqual(right) && ReadAll(b).SequenceEqual(left), "Loss/reordering corrupted either stream");
            Check(a.PeerClosed && b.PeerClosed && a.FailureReason is null && b.FailureReason is null, "Close under loss failed");
        });
        Test("TIME-WAIT ignores resets and local delivery can establish synchronously", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(); a.Close(); n.Pump(); b.Close(); n.Pump();
            a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, 0, TcpFlags.Rst, 0, default));
            Check(a.State == TcpState.TimeWait, "TIME-WAIT was assassinated by RST");
            var m = new Network(); TcpConnection? accepted = null;
            m.TcpA.Listen(90, connection => accepted = connection);
            var local = m.TcpA.Connect(m.A.LocalAddress, 90);
            Check(local.State == TcpState.Established && accepted?.State == TcpState.Established, "Reentrant local delivery failed");
        });
        Test("aborting a simultaneous-open callback stops handshake processing", () =>
        {
            var n = new Network(); var a = n.TcpA.Connect(n.B.LocalAddress, 2000, 1000);
            a.StateChanged += (c, state) => { if (state == TcpState.SynReceived) c.Abort(); };
            n.TcpB.Connect(n.A.LocalAddress, 1000, 2000); n.Pump();
            Check(a.State == TcpState.Closed && n.TcpA.Connections.Count == 0, "Aborted open survived");
        });
        Test("aborting close state callbacks emits only the reset", () =>
        {
            foreach (var passive in new[] { false, true })
            {
                var n = new Network(); var (a, b) = n.Connect();
                if (passive) { b.Close(); n.Pump(); }
                var sequence = a.NextSendSequence;
                a.StateChanged += (c, state) => { if (state is TcpState.FinWait1 or TcpState.LastAck) c.Abort(); };
                a.Close();
                Check(a.State == TcpState.Closed && a.NextSendSequence == sequence, "FIN tracked after abort");
                Check(n.Queue.Count == 1 && TcpSegment.Parse(n.A.LocalAddress, n.B.LocalAddress,
                    n.Queue.Peek().Packet.Payload.Span).Has(TcpFlags.Rst), "Packet emitted after reset");
            }
        });
        Test("aborting establishment suppresses subsequent connected notifications", () =>
        {
            var n = new Network(); n.TcpB.Listen(80, _ => { });
            var a = n.TcpA.Connect(n.B.LocalAddress, 80); var connected = 0;
            a.Connected += _ => connected++;
            a.StateChanged += (c, state) => { if (state == TcpState.Established) c.Abort(); };
            n.Pump(); Check(a.State == TcpState.Closed && connected == 0, "Connected fired after abort");
            var m = new Network();
            m.TcpB.Listen(80, c => { c.Connected += _ => connected++; c.Abort(); });
            m.TcpA.Connect(m.B.LocalAddress, 80); m.Pump();
            Check(connected == 0, "Connected fired after listener aborted");
        });
        Test("aborting receive callbacks prevents further data and EOF notification", () =>
        {
            foreach (var urgent in new[] { false, true })
            {
                var n = new Network(); var (a, b) = n.Connect(); var delivered = 0; var eof = 0;
                a.DataAvailable += c => { delivered++; if (!urgent) c.Abort(); };
                a.UrgentDataAvailable += c => c.Abort(); a.ReadClosed += _ => eof++;
                a.Receive(new TcpSegment(b.LocalPort, a.LocalPort, a.NextReceiveSequence, a.NextSendSequence,
                    TcpFlags.Ack | TcpFlags.Fin | (urgent ? TcpFlags.Urg : 0), 65535, "abc"u8.ToArray(), UrgentPointer: 1));
                Check(a.State == TcpState.Closed && a.Available == 0 && eof == 0 && delivered == (urgent ? 0 : 1),
                    "Receive processing continued after abort");
            }
        });
        Test("fast retransmit postpones the timeout by a full RTO", () =>
        {
            var n = new Network(600); var (a, b) = n.Connect();
            a.Send(new byte[10000]); n.Pump(); ReadAll(b); n.Pump();
            a.Send(new byte[8000]); n.Queue.Dequeue();
            var rest = n.Queue.ToArray(); n.Queue.Clear(); n.Clock.Advance(TimeSpan.FromMilliseconds(900));
            foreach (var item in rest) n.B.Receive(item.Packet.Serialize(), false);
            var acks = n.Queue.ToArray(); n.Queue.Clear();
            foreach (var item in acks) n.A.Receive(item.Packet.Serialize(), false);
            Check(a.Retransmissions == 1, "Fast retransmit not triggered"); n.Queue.Clear();
            n.Clock.Advance(TimeSpan.FromMilliseconds(100)); n.A.Tick();
            Check(a.Retransmissions == 1 && a.RetransmissionTimeoutSeconds == 1, "Old timer retransmitted too early");
            n.Clock.Advance(TimeSpan.FromMilliseconds(900)); n.A.Tick();
            Check(a.Retransmissions == 2 && a.RetransmissionTimeoutSeconds == 2, "Rescheduled timeout did not fire/back off");
        });
        Test("unanswered zero-window probes eventually release a dead connection", () =>
        {
            var n = new Network(); var (a, _) = n.Connect(capacity: 1); a.Send(new byte[10]); n.Pump();
            for (var i = 0; i < 9; i++) { n.Clock.Advance(TimeSpan.FromSeconds(60)); n.A.Tick(); n.Queue.Clear(); }
            Check(a.State == TcpState.Closed && a.BufferedSendBytes == 0 && n.TcpA.Connections.Count == 0 &&
                a.FailureReason!.Contains("probe"), "Silent zero-window peer retained indefinitely");
        });
        Test("responsive zero-window peer stays connected and later resumes", () =>
        {
            var n = new Network(); var (a, b) = n.Connect(capacity: 1); a.Send([1, 2, 3]); n.Pump();
            for (var i = 0; i < 100; i++) n.Advance(60);
            Check(a.State == TcpState.Established && a.FailureReason is null, "Responsive zero-window peer timed out");
            var received = new List<byte>();
            for (var i = 0; i < 10 && received.Count < 3; i++)
            { received.AddRange(ReadAll(b)); n.Pump(); n.Advance(2); }
            Check(received.SequenceEqual(new byte[] { 1, 2, 3 }) && a.BufferedSendBytes == 0, "Window reopening lost bytes");
        });
        Test("FIN-WAIT-2 stays open while the peer keeps sending into the half-close", () =>
        {
            // Regression: the 5-minute FIN-WAIT-2 deadline was never restarted, so a long response to a
            // half-closed request was cut off mid-stream and its unread bytes discarded.
            var n = new Network(); var (a, b) = n.Connect(); a.Close(); n.Pump();
            Check(a.State == TcpState.FinWait2, "Half-close did not reach FIN-WAIT-2");
            var received = new List<byte>();
            for (var i = 0; i < 10; i++) { b.Send([(byte)i]); n.Pump(); received.AddRange(ReadAll(a)); n.Advance(60); }
            Check(a.State == TcpState.FinWait2 && a.FailureReason is null, "Half-close timed out while data was flowing");
            Check(received.SequenceEqual(Enumerable.Range(0, 10).Select(i => (byte)i)), "Half-close lost data");
            n.Advance(301); Check(a.State == TcpState.Closed && a.FailureReason!.Contains("FIN-WAIT-2"), "Silent peer not released");
        });
        Test("path MTU drop resends the whole oversized flight without waiting for timeouts", () =>
        {
            // Regression: only the first MSS of each oversized segment was resent; the rest waited an RTO per chunk.
            var n = new Network(); var (a, b) = n.Connect(); var data = new byte[3 * a.MaximumSegmentSize]; Random.Shared.NextBytes(data);
            a.Send(data); var original = n.Queue.Peek().Packet; n.Queue.Clear(); n.History.Clear(); // Router dropped the flight.
            var error = new TCP.L3.Network.Icmp.IcmpPacket(3, 4, 600, original.Serialize()[..28]);
            n.A.Receive(new IPv4Packet(0, 123, 0, 64, 1, n.B.LocalAddress, n.A.LocalAddress, default, error.Serialize()).Serialize(), false);
            n.Pump();
            Check(ReadAll(b).SequenceEqual(data), "Oversized flight not resent before the retransmission timer");
            n.AdvanceMilliseconds(200); // The receiver's final ACK is a delayed one.
            Check(n.History.All(p => p.TotalLength <= 600) && a.BufferedSendBytes == 0, "Resend exceeded the new path MTU");
        });
        Test("zero receive window still honors the ACK on a zero-window probe", () =>
        {
            // Regression: with RCV.WND = 0 every data-bearing segment was rejected before the ACK step, so a
            // peer that acknowledged only on its probes looked silent and our retransmissions timed out.
            var n = new Network(); var (a, b) = n.Connect(capacity: 8);
            a.Send(new byte[8]); n.Pump(); Check(b.ReceiveWindow == 0, "Receiver window did not fill");
            b.Send("reply"u8); n.Queue.Clear(); // A's acknowledgment of the reply will come only on its probe.
            b.Receive(new TcpSegment(a.LocalPort, b.LocalPort, b.NextReceiveSequence, b.NextSendSequence, TcpFlags.Ack, 65535, new byte[] { 9 }));
            Check(b.BufferedSendBytes == 0, "ACK on zero-window probe ignored");
            Check(b.Available == 8 && n.Queue.Count == 1, "Probe byte was buffered or not re-acknowledged");
        });
        RunExtensionTests(Test);
        return passed;
        void Test(string name, Action body) { body(); passed++; Console.WriteLine($"PASS: TCP {name}"); }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Throws(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new Exception("Expected validation failure");
    }
    private static byte[] ReadAll(TcpConnection connection) { var bytes = new byte[connection.Available]; connection.Read(bytes); return bytes; }
    internal sealed class Link(Action<IPv4Packet> send) : IIPv4Link
    {
        public bool IsReady => true;
        public void SendBroadcast(IPv4Packet packet) => throw new Exception("TCP attempted broadcast");
        public void SendToNeighbor(IPAddress nextHop, IPv4Packet packet) => send(packet);
    }
    internal sealed class Network
    {
        public readonly FakeTime Clock = new();
        public readonly Queue<(bool FromA, IPv4Packet Packet)> Queue = new();
        public readonly List<IPv4Packet> History = [];
        public readonly IPv4Host A, B;
        public readonly TcpHost TcpA, TcpB;
        /// <summary>Rewrites or drops (returns null) each packet as it is delivered; null delivers unchanged.</summary>
        public Func<bool, IPv4Packet, IPv4Packet?>? Filter;
        public Network(int mtu = 1500, TcpSettings? settings = null, TcpSettings? settingsB = null)
        {
            var a = IPAddress.Parse("192.0.2.1"); var b = IPAddress.Parse("192.0.2.2"); var subnet = new IPv4Subnet(a, IPAddress.Parse("255.255.255.0"));
            A = new IPv4Host(new Link(p => { Queue.Enqueue((true, p)); History.Add(p); }), a, subnet, Clock, mtu);
            B = new IPv4Host(new Link(p => { Queue.Enqueue((false, p)); History.Add(p); }), b, subnet, Clock, mtu);
            TcpA = new TcpHost(A, settings); TcpB = new TcpHost(B, settingsB ?? settings);
        }
        public (TcpConnection A, TcpConnection B) Connect(int capacity = 65535)
        {
            TcpConnection? b = null; TcpB.Listen(80, connection => b = connection, receiveCapacity: capacity);
            var a = TcpA.Connect(B.LocalAddress, 80); Pump();
            Check(a.State == TcpState.Established && b?.State == TcpState.Established, "Handshake failed"); return (a, b!);
        }
        public void DeliverNext()
        {
            var item = Queue.Dequeue();
            var packet = Filter is null ? item.Packet : Filter(item.FromA, item.Packet);
            if (packet is { } delivered) (item.FromA ? B : A).Receive(delivered.Serialize(), false);
        }
        public void Pump() { var count = 0; while (Queue.Count > 0) { if (++count > 10000) throw new Exception("ACK loop"); DeliverNext(); } }
        public void Advance(int seconds) { Clock.Advance(TimeSpan.FromSeconds(seconds)); A.Tick(); B.Tick(); Pump(); }
        public void AdvanceMilliseconds(int milliseconds) { Clock.Advance(TimeSpan.FromMilliseconds(milliseconds)); A.Tick(); B.Tick(); Pump(); }
    }
}
