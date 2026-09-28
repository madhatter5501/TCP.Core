using System.Buffers.Binary;
using System.Net;
using System.Text;
using TCP.Checksums;
using TCP.L1.Physical;
using TCP.L2.Link.Arp;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.Icmp;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;
using TCP.L3.Network.IPv4.Routing;
using TCP.Stack;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.Explorer;

public sealed record SimulationRequest(string Scenario = "ping", string Message = "Hello from TCP.Core!", int PayloadBytes = 32, int Mtu = 1500);
public sealed record TraceEvent(double TimeMs, string Kind, string Message);
public sealed record PacketField(string Name, string Value, int Offset, int Bytes);
/// <summary>A contiguous span of the frame owned by one header or payload, for the inspector's byte map.</summary>
public sealed record FrameSection(string Name, int Offset, int Bytes);
public sealed record CapturedFrame(int Number, double TimeMs, string From, string To, string Protocol,
    string Delivery, string Explanation, int Length, string SentHex, string ReceivedHex, List<PacketField> Fields, List<FrameSection> Sections);
public sealed record SimulationResult(string Scenario, bool SendAccepted, bool EchoAnswered, bool ReplyVerified,
    string Outcome, int PayloadBytes, int Mtu, double VirtualDurationMs, List<TraceEvent> Events, List<CapturedFrame> Frames, int TcpRetransmissions = 0);

/// <summary>
/// Runs production protocol code against an isolated in-memory link. Like the Core tests,
/// drives receive/timer hooks on one thread; addresses are preassigned (no Run/address claim).
/// Every request owns its stacks, queues and clock. Nothing opens a physical interface.
/// </summary>
public static class TransmissionSimulation
{
    private static readonly HashSet<string> Scenarios = ["ping", "fragment", "df", "checksum", "loss", "arp-loss", "tcp", "tcp-loss", "tcp-checksum", "tcp-window", "tcp-refused"];

    public static SimulationResult Run(SimulationRequest request)
    {
        if (request.Scenario is null || !Scenarios.Contains(request.Scenario)) throw new ArgumentException("Choose a supported scenario.");
        if (request.Mtu is < 68 or > 9000) throw new ArgumentException("MTU must be between 68 and 9000 bytes.");
        if (request.PayloadBytes is < 1 or > 8192) throw new ArgumentException("Payload must be between 1 and 8192 bytes.");
        if (string.IsNullOrEmpty(request.Message) || request.Message.Length > 1024) throw new ArgumentException("Enter a message between 1 and 1024 characters.");
        if (request.Scenario is "fragment" or "df" or "loss" && request.PayloadBytes + 28 <= request.Mtu)
            throw new ArgumentException("For this scenario, payload + 28 bytes must exceed the MTU. Increase the payload or lower the MTU.");
        if (request.Scenario.StartsWith("tcp", StringComparison.Ordinal)) return RunTcp(request);

        var clock = new SimulationClock();
        var frames = new List<CapturedFrame>();
        var events = new List<TraceEvent>();
        var queue = new Queue<(bool FromA, byte[] Bytes)>();
        using var portA = new MemoryPort("virtual-a", bytes => queue.Enqueue((true, [.. bytes])));
        using var portB = new MemoryPort("virtual-b", bytes => queue.Enqueue((false, [.. bytes])));
        var addressA = IPAddress.Parse("192.0.2.10");
        var addressB = IPAddress.Parse("192.0.2.20");
        var subnet = new IPv4Subnet(addressA, IPAddress.Parse("255.255.255.0"));
        using var a = new EthernetStack(portA, addressA, MacAddress.FromBytes([2, 0, 0, 0, 0, 10]), subnet, clock, request.Mtu);
        using var b = new EthernetStack(portB, addressB, MacAddress.FromBytes([2, 0, 0, 0, 0, 20]), subnet, clock, request.Mtu);
        var seed = Encoding.UTF8.GetBytes(request.Message);
        var payload = new byte[request.PayloadBytes];
        for (var i = 0; i < payload.Length; i++) payload[i] = seed[i % seed.Length];
        var answered = false;
        var verified = false;
        var resolutionFailed = false;
        var faultInjected = false;
        var icmpError = false;
        // Passive observer uses the production reassembler and ICMP checksum parser.
        // IPv4Host currently has no echo-reply event, so reply verification belongs here.
        var observer = new IPv4Reassembler(clock);
        b.IPv4.EchoRequestAnswered += (_, _) => { answered = true; Note("core", "Host B: EchoRequestAnswered fired after reassembly and ICMP validation."); };
        a.NeighborResolutionFailed += ip => { resolutionFailed = true; Note("core", $"Host A: NeighborResolutionFailed for {ip} after ARP retries."); };
        a.IPv4.IcmpErrorReceived += (_, message) => { icmpError = true; Note("core", $"Host A: IcmpErrorReceived type {message.Type}, code {message.Code}."); };
        Note("setup", "Two TCP.Core EthernetStack instances; static /24 addresses, empty ARP caches, virtual clock. No physical NIC or startup address claim.");
        Note("payload", $"UTF-8 message bytes repeated/truncated to {payload.Length} bytes, wrapped by IcmpPacket.CreateEchoRequest (identifier 42, sequence 1).");
        var datagram = new IPv4Packet(0, 0, request.Scenario == "df" ? IPv4FragmentField.DontFragmentFlag : (ushort)0,
            64, 1, addressA, addressB, ReadOnlyMemory<byte>.Empty, IcmpPacket.CreateEchoRequest(42, 1, payload).Serialize());
        var accepted = a.IPv4.SendIPv4(datagram);
        Note("core", $"Host A: IPv4Host.SendIPv4 returned {accepted.ToString().ToLowerInvariant()} for a {datagram.TotalLength}-byte datagram.");

        Drain();
        // Advance protocol time, not wall time: ARP retries and the 60-second reassembly timeout.
        for (var second = 1; accepted && !verified && !resolutionFailed && !icmpError && second <= 61; second++)
        {
            clock.Advance(); a.Tick(); b.Tick(); Drain();
        }
        var outcome = verified ? "Echo reply verified byte for byte."
            : !accepted ? "Send rejected by TCP.Core: the datagram exceeds MTU with DF set. No frame was emitted."
            : resolutionFailed ? "ARP resolution failed after the real retry sequence; no IP packet was sent."
            : icmpError ? "No echo reply. The receiver’s reassembly timer expired and an ICMP error reached the sender."
            : "No echo reply within 61 virtual seconds. Inspect the trace and received bytes for the injected fault.";
        Note("outcome", outcome);
        return new SimulationResult(request.Scenario, accepted, answered, verified, outcome, payload.Length, request.Mtu, clock.Milliseconds, events, frames);

        void Note(string kind, string message) => events.Add(new TraceEvent(clock.Milliseconds, kind, message));

        void Drain()
        {
            while (queue.TryDequeue(out var transmission))
            {
                if (frames.Count >= 512) throw new InvalidOperationException("Simulation frame budget exceeded.");
                var (fromA, original) = transmission;
                var received = original.ToArray();
                var frame = EthernetFrame.Parse(original);
                IPv4Packet? packet = frame.EtherType == (ushort)EtherType.IPv4 ? IPv4Packet.Parse(frame.Payload.Span) : null;
                var drop = request.Scenario == "arp-loss" && !fromA && frame.EtherType == (ushort)EtherType.Arp;
                var explanation = drop ? "Virtual link discards this ARP reply; the sender’s retry timer remains active." : "Bytes passed unchanged to the peer’s EthernetStack.ProcessFrame.";
                var delivery = drop ? "Dropped" : "Delivered";
                if (!faultInjected && fromA && packet is { } ip)
                {
                    if (request.Scenario == "checksum")
                    {
                        received[EthernetConstants.HeaderLength + 10] ^= 1;
                        faultInjected = true;
                        delivery = "Corrupted";
                        explanation = "Virtual link flips one IPv4 checksum bit (frame byte 24). The receiver gets these modified bytes.";
                    }
                    else if (request.Scenario == "loss" && (ip.FlagsAndFragmentOffset & IPv4FragmentField.FragmentOffsetMask) != 0)
                    {
                        faultInjected = true; drop = true; delivery = "Dropped";
                        explanation = "Virtual link discards one non-first fragment. The receiver cannot complete reassembly.";
                    }
                }
                var capture = Describe(frames.Count + 1, clock.Milliseconds, fromA, original, received, delivery, explanation, drop);
                frames.Add(capture);
                Note("frame", $"#{capture.Number} {capture.From} → {capture.To}: {capture.Protocol}, {capture.Length} bytes; {delivery.ToLowerInvariant()}.");
                if (drop) continue;
                (fromA ? b : a).ProcessFrame(received);
                if (!fromA && packet is { Protocol: 1 } reply &&
                    observer.TryAccept(reply, false, out var complete, out _))
                {
                    var message = IcmpPacket.Parse(complete.Payload.Span);
                    if (message.Type == IcmpPacket.EchoReplyType && message.Identifier == 42 && message.SequenceNumber == 1 &&
                        complete.SourceAddress.Equals(addressB) && complete.DestinationAddress.Equals(addressA) && message.Payload.Span.SequenceEqual(payload))
                    {
                        verified = true;
                        Note("verified", $"Reply verified from captured bytes: checksum valid, identifier/sequence match, all {payload.Length} payload bytes identical.");
                    }
                }
            }
        }
    }

    private static CapturedFrame Describe(int number, double time, bool fromA, byte[] sent, byte[] received, string delivery, string explanation, bool dropped)
    {
        var frame = EthernetFrame.Parse(received);
        var fields = new List<PacketField>
        {
            new("Destination MAC", frame.Destination.ToString(), 0, 6),
            new("Source MAC", frame.Source.ToString(), 6, 6),
            new("EtherType", $"0x{frame.EtherType:X4}", 12, 2)
        };
        List<FrameSection> sections = [new("Ethernet header", 0, 14)];
        var protocol = "Ethernet";
        if (frame.EtherType == (ushort)EtherType.Arp)
        {
            var arp = ArpPacket.Parse(frame.Payload.Span);
            protocol = arp.Operation == ArpOperation.Request ? "ARP request" : "ARP reply";
            fields.AddRange([
                new PacketField("ARP operation", arp.Operation.ToString(), 20, 2),
                new PacketField("Sender MAC", arp.SenderHardwareAddress.ToString(), 22, 6),
                new PacketField("Sender IPv4", arp.SenderProtocolAddress.ToString(), 28, 4),
                new PacketField("Target MAC", arp.TargetHardwareAddress.ToString(), 32, 6),
                new PacketField("Target IPv4", arp.TargetProtocolAddress.ToString(), 38, 4),
                new PacketField("Ethernet padding", "Outside the 28-byte ARP message", 42, sent.Length - 42)
            ]);
            sections.Add(new("ARP message", 14, 28));
            if (sent.Length > 42) sections.Add(new("Ethernet padding", 42, sent.Length - 42));
        }
        else if (frame.EtherType == (ushort)EtherType.IPv4)
        {
            var bytes = frame.Payload.Span;
            var headerLength = (bytes[0] & 15) * 4;
            var length = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
            var flags = BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]);
            var offset = (flags & IPv4FragmentField.FragmentOffsetMask) * 8;
            var fragmented = (flags & IPv4FragmentField.ReassemblyMask) != 0;
            var isTcp = bytes[9] == 6;
            protocol = fragmented ? $"IPv4 fragment · offset {offset} B" : isTcp ? $"TCP {((TcpFlags)bytes[headerLength + 13]).ToString().ToUpperInvariant()}" : bytes[20] == 8 ? "ICMP echo request" : bytes[20] == 0 ? "ICMP echo reply" : $"ICMP type {bytes[20]} / code {bytes[21]}";
            fields.AddRange([
                new PacketField("Version / header length", $"IPv4 / {headerLength} B", 14, 1),
                new PacketField("Total IP length", $"{length} B", 16, 2),
                new PacketField("Identification", BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]).ToString(), 18, 2),
                new PacketField("Flags / fragment offset", $"DF {((flags & 0x4000) != 0 ? 1 : 0)}, MF {((flags & 0x2000) != 0 ? 1 : 0)}, offset {offset} B ({offset / 8} units)", 20, 2),
                new PacketField("TTL / IP protocol", $"{bytes[8]} / {bytes[9]} ({(isTcp ? "TCP" : "ICMP")})", 22, 2),
                new PacketField("IPv4 checksum", InternetChecksum.IsValid(bytes[..headerLength]) ? "Valid" : "INVALID — receiver rejects header", 24, 2),
                new PacketField("Source IPv4", new IPAddress(bytes.Slice(12, 4)).ToString(), 26, 4),
                new PacketField("Destination IPv4", new IPAddress(bytes.Slice(16, 4)).ToString(), 30, 4)
            ]);
            var transportHeaderLength = fragmented ? 0 : 8;
            if (!fragmented && isTcp)
            {
                var tcp = bytes.Slice(headerLength, length - headerLength);
                var start = 14 + headerLength;
                transportHeaderLength = (tcp[12] >> 4) * 4;
                var valid = true;
                try { TcpSegment.Parse(new IPAddress(bytes.Slice(12, 4)), new IPAddress(bytes.Slice(16, 4)), tcp); }
                catch (ArgumentException) { valid = false; }
                fields.AddRange([
                    new PacketField("Source / destination port", $"{BinaryPrimitives.ReadUInt16BigEndian(tcp)} → {BinaryPrimitives.ReadUInt16BigEndian(tcp[2..])}", start, 4),
                    new PacketField("Sequence number", BinaryPrimitives.ReadUInt32BigEndian(tcp[4..]).ToString(), start + 4, 4),
                    new PacketField("Acknowledgment number", BinaryPrimitives.ReadUInt32BigEndian(tcp[8..]).ToString(), start + 8, 4),
                    new PacketField("Header length / flags", $"{transportHeaderLength} B / {(TcpFlags)tcp[13]}", start + 12, 2),
                    new PacketField("Receive window", $"{BinaryPrimitives.ReadUInt16BigEndian(tcp[14..])} B", start + 14, 2),
                    new PacketField("TCP checksum (IPv4 pseudo-header included)", valid ? "Valid" : "INVALID — receiver drops segment", start + 16, 2),
                    new PacketField("Urgent pointer", BinaryPrimitives.ReadUInt16BigEndian(tcp[18..]).ToString(), start + 18, 2)
                ]);
                if (transportHeaderLength > 20) fields.Add(new PacketField("TCP options (MSS in SYN)", Convert.ToHexString(tcp[20..transportHeaderLength]), start + 20, transportHeaderLength - 20));
            }
            else if (!fragmented)
            {
                fields.Add(new PacketField("ICMP type / code", $"{bytes[20]} / {bytes[21]}", 34, 2));
                fields.Add(new PacketField("ICMP checksum", InternetChecksum.IsValid(bytes.Slice(headerLength, length - headerLength)) ? "Valid" : "Invalid", 36, 2));
                fields.Add(new PacketField("ICMP rest of header", $"0x{BinaryPrimitives.ReadUInt32BigEndian(bytes[24..]):X8}", 38, 4));
            }
            var dataLength = length - headerLength - transportHeaderLength;
            if (dataLength > 0) fields.Add(new PacketField(fragmented ? "IP fragment payload" : isTcp ? "TCP stream data" : "ICMP data", $"{dataLength} B", 14 + headerLength + transportHeaderLength, dataLength));
            if (sent.Length > 14 + length) fields.Add(new PacketField("Ethernet padding", "Excluded from IP total length", 14 + length, sent.Length - 14 - length));
            sections.Add(new("IPv4 header", 14, headerLength));
            if (transportHeaderLength > 0) sections.Add(new(isTcp ? "TCP header" : "ICMP header", 14 + headerLength, transportHeaderLength));
            if (dataLength > 0) sections.Add(new(fragmented ? "Fragment payload" : isTcp ? "TCP data" : "ICMP data", 14 + headerLength + transportHeaderLength, dataLength));
            if (sent.Length > 14 + length) sections.Add(new("Ethernet padding", 14 + length, sent.Length - 14 - length));
        }
        else if (sent.Length > 14) sections.Add(new("Payload", 14, sent.Length - 14));
        return new CapturedFrame(number, time, fromA ? "Host A" : "Host B", fromA ? "Host B" : "Host A", protocol, delivery, explanation,
            sent.Length, Convert.ToHexString(sent), dropped ? "" : Convert.ToHexString(received), fields, sections);
    }

    private static SimulationResult RunTcp(SimulationRequest request)
    {
        var clock = new SimulationClock();
        var events = new List<TraceEvent>(); var frames = new List<CapturedFrame>();
        var queue = new Queue<(bool FromA, byte[] Bytes)>();
        var addressA = IPAddress.Parse("192.0.2.10"); var addressB = IPAddress.Parse("192.0.2.20");
        var subnet = new IPv4Subnet(addressA, IPAddress.Parse("255.255.255.0"));
        using var a = new EthernetStack(new MemoryPort("tcp-a", bytes => queue.Enqueue((true, [.. bytes]))), addressA,
            MacAddress.FromBytes([2, 0, 0, 0, 0, 10]), subnet, clock, request.Mtu);
        using var b = new EthernetStack(new MemoryPort("tcp-b", bytes => queue.Enqueue((false, [.. bytes]))), addressB,
            MacAddress.FromBytes([2, 0, 0, 0, 0, 20]), subnet, clock, request.Mtu);
        var seed = Encoding.UTF8.GetBytes(request.Message); var payload = new byte[request.PayloadBytes];
        for (var i = 0; i < payload.Length; i++) payload[i] = seed[i % seed.Length];
        var serverBytes = new List<byte>(); var clientBytes = new List<byte>();
        TcpConnection? server = null;
        var injected = false;
        if (request.Scenario != "tcp-refused") b.Tcp.Listen(8080, connection =>
        {
            server = connection; Note("core", $"Host B accepted TCP connection; MSS {connection.MaximumSegmentSize} B.");
            connection.StateChanged += (_, state) => Note("state", $"Host B: {state}");
            connection.DataAvailable += Echo;
            connection.ReadClosed += c => { Echo(c); c.Close(); };
        }, receiveCapacity: request.Scenario == "tcp-window" ? 256 : 65535);
        Note("setup", "Real TCP endpoints on virtual Ethernet: Host A :50000 → Host B :8080. Empty ARP caches; static addresses; no physical NIC.");
        var client = a.Tcp.Connect(addressB, 8080, 50000);
        Note("state", "Host A: SynSent");
        client.StateChanged += (_, state) => Note("state", $"Host A: {state}");
        client.Connected += connection =>
        {
            Note("core", $"Host A connected; negotiated send MSS {connection.MaximumSegmentSize} B. Queuing {payload.Length} bytes and half-closing.");
            connection.Send(payload); connection.Close();
        };
        client.DataAvailable += connection => { var bytes = new byte[connection.Available]; connection.Read(bytes); clientBytes.AddRange(bytes); };
        Drain();
        for (var second = 1; second <= 61 && client.State is not (TcpState.TimeWait or TcpState.Closed); second++)
        {
            clock.Advance(); a.Tick(); b.Tick();
            if (server is { Available: > 0 } && request.Scenario == "tcp-window" && clock.Milliseconds >= 2000) Echo(server);
            Drain();
        }
        var verified = client.PeerClosed && clientBytes.SequenceEqual(payload) && serverBytes.SequenceEqual(payload);
        var outcome = verified ? $"TCP stream verified byte for byte; FIN exchange completed. {client.Retransmissions} sender retransmission(s). Host A: {client.State}; Host B: {server?.State}."
            : client.FailureReason ?? "TCP did not complete within 61 virtual seconds; inspect the trace.";
        Note("outcome", outcome);
        // Snapshot before disposing endpoints so local cleanup is not confused with wire behavior.
        return new SimulationResult(request.Scenario, client.FailureReason is null, serverBytes.SequenceEqual(payload), verified,
            outcome, payload.Length, request.Mtu, clock.Milliseconds, [.. events], [.. frames], client.Retransmissions);

        void Note(string kind, string message) => events.Add(new TraceEvent(clock.Milliseconds, kind, message));

        void Echo(TcpConnection connection)
        {
            if (request.Scenario == "tcp-window" && clock.Milliseconds < 2000) return;
            var bytes = new byte[connection.Available]; connection.Read(bytes); serverBytes.AddRange(bytes);
            if (bytes.Length > 0) { connection.Send(bytes); Note("application", $"Echo application read and queued {bytes.Length} stream bytes on Host B."); }
        }

        void Drain()
        {
            while (queue.TryDequeue(out var item))
            {
                if (frames.Count >= 4096) throw new InvalidOperationException("TCP simulation frame budget exceeded.");
                var original = item.Bytes; var received = original.ToArray();
                var frame = EthernetFrame.Parse(original); var delivery = "Delivered";
                var explanation = "Serialized by TCP.Core and passed unchanged to the peer’s EthernetStack.ProcessFrame.";
                if (!injected && item.FromA && frame.EtherType == (ushort)EtherType.IPv4)
                {
                    var packet = IPv4Packet.Parse(frame.Payload.Span);
                    if (packet.Protocol == 6 && TcpSegment.Parse(packet.SourceAddress, packet.DestinationAddress, packet.Payload.Span).Payload.Length > 0)
                    {
                        if (request.Scenario == "tcp-loss")
                        { injected = true; delivery = "Dropped"; explanation = "The virtual link drops the first TCP data segment. ACK/retransmission logic must recover it."; }
                        if (request.Scenario == "tcp-checksum")
                        { injected = true; received[14 + packet.HeaderLength + 16] ^= 1; delivery = "Corrupted"; explanation = "The virtual link flips one TCP checksum bit. IPv4 remains valid; TCP must reject and retransmit the segment."; }
                    }
                }
                var capture = Describe(frames.Count + 1, clock.Milliseconds, item.FromA, original, received, delivery, explanation, delivery == "Dropped");
                frames.Add(capture); Note("frame", $"#{capture.Number} {capture.From} → {capture.To}: {capture.Protocol}, {capture.Length} B; {delivery.ToLowerInvariant()}.");
                if (delivery != "Dropped") (item.FromA ? b : a).ProcessFrame(received);
            }
        }
    }

    private sealed class MemoryPort(string name, Action<byte[]> send) : IPacketInterface
    {
        public string InterfaceName => name;
        public int Receive(byte[] buffer) => 0; // Simulator delivers queued frames through the receive hook.
        public void Send(byte[] frame) => send(frame);
        public void Dispose() { }
    }
    private sealed class SimulationClock : TimeProvider
    {
        public double Milliseconds { get; private set; }
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddMilliseconds(Milliseconds);
        public void Advance() => Milliseconds += 1000;
    }
}
