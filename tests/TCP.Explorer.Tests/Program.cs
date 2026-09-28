using TCP.Explorer;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.Icmp;

var passed = 0;

Test("Ping exchanges real ARP and checksum-valid ICMP frames", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest(Message: "real bytes"));
    Check(run.SendAccepted && run.EchoAnswered && run.ReplyVerified, "Ping failed");
    Check(run.Frames.Count == 4, "Expected ARP request/reply followed by echo request/reply");
    foreach (var capture in run.Frames)
    {
        Check(capture.SentHex == capture.ReceivedHex, "Unmodified link changed bytes");
        var frame = EthernetFrame.Parse(Convert.FromHexString(capture.SentHex));
        if (frame.EtherType == 0x0800)
        {
            var ip = IPv4Packet.Parse(frame.Payload.Span);
            var icmp = IcmpPacket.Parse(ip.Payload.Span);
            Check(icmp.Payload.Length == 32 && icmp.Identifier == 42 && icmp.SequenceNumber == 1, "Echo payload metadata differs");
        }
    }
});
Test("Large echo reassembles before the receiver responds", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("fragment", "abc", 4000));
    Check(run.ReplyVerified && run.EchoAnswered, "Fragmented ping failed");
    Check(run.Frames.Count(frame => frame.Protocol.StartsWith("IPv4 fragment")) == 6, "Expected three fragments each direction");
    Check(run.Frames.All(frame => frame.Length <= 1514), "MTU not respected");
});
Test("DF refusal emits no Ethernet frame", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("df", "abc", 4000));
    Check(!run.SendAccepted && !run.ReplyVerified && run.Frames.Count == 0, "DF did not block send");
});
Test("One checksum bit changes and the real receiver drops it", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("checksum"));
    var bad = run.Frames.Single(frame => frame.Delivery == "Corrupted");
    var sent = Convert.FromHexString(bad.SentHex);
    var received = Convert.FromHexString(bad.ReceivedHex);
    Check(sent.Zip(received).Count(pair => pair.First != pair.Second) == 1 && sent[24] != received[24], "Wrong fault injection");
    Check(!run.EchoAnswered && !run.ReplyVerified && run.VirtualDurationMs == 61000, "Bad header was answered");
    Check(bad.Fields.Any(field => field.Name == "IPv4 checksum" && field.Value.StartsWith("INVALID")), "Inspector hid invalid checksum");
});
Test("A missing fragment triggers the core reassembly timeout and ICMP error", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("loss", "abc", 4000));
    Check(!run.EchoAnswered && !run.ReplyVerified, "Incomplete datagram was answered");
    Check(run.Frames.Count(frame => frame.Delivery == "Dropped") == 1, "Wrong number of losses");
    Check(run.Events.Any(entry => entry.Message.Contains("IcmpErrorReceived type 11, code 1")), "No real reassembly error observed");
    Check(run.VirtualDurationMs == 60000, "Unexpected reassembly lifetime");
});
Test("Byte-map sections tile every captured frame", () =>
{
    foreach (var scenario in new[] { "ping", "fragment", "arp-loss", "tcp" })
        foreach (var frame in TransmissionSimulation.Run(new SimulationRequest(scenario, "abc", 4000)).Frames)
        {
            var next = 0;
            foreach (var section in frame.Sections)
            {
                Check(section.Offset == next && section.Bytes > 0, $"{scenario} #{frame.Number}: gap or overlap at {section.Name}");
                next += section.Bytes;
            }
            Check(next == frame.Length, $"{scenario} #{frame.Number}: sections cover {next} of {frame.Length} B");
        }
});
Test("ARP retries three times and reports resolution failure", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("arp-loss"));
    Check(run.Frames.Count(frame => frame.Protocol == "ARP request") == 3, "Unexpected retry count");
    Check(run.Frames.All(frame => frame.Protocol.StartsWith("ARP")), "IP sent without resolution");
    Check(run.Events.Any(entry => entry.Message.Contains("NeighborResolutionFailed")), "Missing failure event");
});
Test("UTF-8 payloads and concurrent runs remain isolated", () =>
{
    Parallel.For(0, 8, i => {
        var run = TransmissionSimulation.Run(new SimulationRequest("ping", "é🙂<script>", 1 + i));
        Check(run.ReplyVerified && run.PayloadBytes == i + 1 && run.Frames.Count == 4, "State leaked between runs");
    });
});
Test("Input limits reject invalid or misleading scenarios", () =>
{
    foreach (var input in new[] { new SimulationRequest(Mtu: 67), new SimulationRequest(PayloadBytes: 8193), new SimulationRequest(Message: ""), new SimulationRequest(Scenario: "unknown"), new SimulationRequest(Scenario: "loss", PayloadBytes: 10) })
    {
        try { TransmissionSimulation.Run(input); throw new Exception("Invalid input accepted"); }
        catch (ArgumentException) { }
    }
});
foreach (var scenario in new[] { "tcp", "tcp-loss", "tcp-checksum", "tcp-window" })
{
    Test($"{scenario} uses real TCP to transfer, echo and close", () =>
    {
        var run = TransmissionSimulation.Run(new SimulationRequest(scenario, "TCP é🙂", 4000));
        Check(run.ReplyVerified && run.EchoAnswered, run.Outcome);
        Check(run.Outcome.Contains("TimeWait") && run.Outcome.Contains("Closed"), "Close handshake incomplete");
        Check(run.Frames.Any(f => f.Protocol.Contains("SYN")) && run.Frames.Any(f => f.Protocol.Contains("FIN")), "Handshake frames missing");
        Check(run.Frames.All(f => !f.Protocol.Contains("fragment")), "TCP should segment rather than IP-fragment");
        if (scenario is "tcp-loss" or "tcp-checksum")
        {
            Check(run.Frames.Count(f => f.Delivery != "Delivered") == 1, "Fault missing or repeated");
            Check(run.TcpRetransmissions > 0, "Expected timer or fast-retransmit recovery");
        }
        if (scenario == "tcp-window") Check(run.Frames.Any(f => f.Fields.Any(field => field.Name == "Receive window" && field.Value == "0 B")), "Zero window not captured");
    });
}
Test("TCP closed port produces a real reset", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("tcp-refused"));
    Check(!run.ReplyVerified && run.Outcome == "Connection refused." && run.Frames.Any(f => f.Protocol.Contains("RST")), "Refusal not captured");
});
Test("TCP smallest MTU and maximum payload remain within capture budget", () =>
{
    var run = TransmissionSimulation.Run(new SimulationRequest("tcp", "bytes", 8192, 68));
    Check(run.ReplyVerified && run.Frames.Count < 4096, run.Outcome);
});
Console.WriteLine($"{passed} transmission tests passed.");
return;

void Check(bool value, string message) { if (!value) throw new Exception(message); }

void Test(string name, Action test) { test(); passed++; Console.WriteLine($"PASS: {name}"); }
