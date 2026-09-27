using TCP.L2.Link.Bridge;
using TCP.L2.Link.Ethernet;
using TCP.L1.Physical;

namespace TCP.Tests;

internal static class BridgeTests
{
    public static int Run()
    {
        var count = 0;
        var a = MacAddress.FromBytes([2, 0, 0, 0, 0, 1]);
        var b = MacAddress.FromBytes([2, 0, 0, 0, 0, 2]);
        var c = MacAddress.FromBytes([2, 0, 0, 0, 0, 3]);

        Test("bridge learns, forwards unicast, floods, and filters same-port frames", () =>
        {
            var ports = new[] { new Port("p0"), new Port("p1"), new Port("p2") };
            using var bridge = new LearningBridge(ports.Select(p => Access(p)));
            var original = Frame(a, b); bridge.ProcessFrame(0, original);
            Check(ports[0].Sent.Count == 0 && ports[1].Sent.Count == 1 && ports[2].Sent.Count == 1, "Unknown destination not flooded");
            foreach (var port in ports) port.Sent.Clear();
            bridge.ProcessFrame(1, Frame(b, a));
            Check(ports[0].Sent.Count == 1 && ports[2].Sent.Count == 0, "Known unicast flooded");
            foreach (var port in ports) port.Sent.Clear();
            bridge.ProcessFrame(0, Frame(c, a));
            Check(ports.All(p => p.Sent.Count == 0), "Same-port destination forwarded");
            bridge.ProcessFrame(0, original);
            Check(ports[1].Sent.Single().AsSpan().SequenceEqual(original), "Bridge altered IP TTL or packet bytes");
        });
        Test("bridge MAC aging and MAC movement", () =>
        {
            var time = new FakeTime(); var ports = new[] { new Port("p0"), new Port("p1"), new Port("p2") };
            using var bridge = new LearningBridge(ports.Select(p => Access(p)), time);
            bridge.ProcessFrame(0, Frame(a, b)); bridge.ProcessFrame(2, Frame(a, b));
            foreach (var port in ports) port.Sent.Clear();
            bridge.ProcessFrame(1, Frame(b, a)); Check(ports[2].Sent.Count == 1 && ports[0].Sent.Count == 0, "MAC move ignored");
            time.Advance(TimeSpan.FromMinutes(6)); foreach (var port in ports) port.Sent.Clear();
            bridge.ProcessFrame(1, Frame(b, a)); Check(ports[2].Sent.Count == 1 && ports[0].Sent.Count == 1, "Aged entry retained");
        });
        Test("VLAN access/trunk isolation and tag conversion", () =>
        {
            var p0 = new Port("p0"); var p1 = new Port("p1"); var p2 = new Port("p2");
            using var bridge = new LearningBridge([Access(p0, 10), Access(p1, 20), new BridgePort(p2, 10, new HashSet<ushort> { 10, 20 }, true)]);
            bridge.ProcessFrame(0, Frame(a, MacAddress.Broadcast));
            Check(p1.Sent.Count == 0 && EthernetFrame.Parse(p2.Sent.Single()).VlanTag == 10, "VLAN leak or missing trunk tag");
            p2.Sent.Clear(); bridge.ProcessFrame(2, Frame(b, a, 10));
            Check(p0.Sent.Count == 1 && !EthernetFrame.Parse(p0.Sent.Single()).VlanTag.HasValue, "Access egress wasn't untagged");
            p0.Sent.Clear(); bridge.ProcessFrame(0, Frame(a, b, 20));
            Check(p2.Sent.Count == 0 && p1.Sent.Count == 0, "Access port accepted another VLAN");
        });
        Test("link-local bridge control frames are not flooded", () =>
        {
            var p0 = new Port("p0"); var p1 = new Port("p1");
            using var bridge = new LearningBridge([Access(p0), Access(p1)]);
            bridge.ProcessFrame(0, Frame(a, MacAddress.FromBytes([1, 0x80, 0xC2, 0, 0, 0])));
            Check(p1.Sent.Count == 0, "Bridge forwarded a reserved control group");
        });
        return count;

        void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
        void Test(string name, Action test) { test(); count++; Console.WriteLine("PASS: " + name); }

        byte[] Frame(MacAddress source, MacAddress destination, ushort? vlan = null) =>
            new EthernetFrame(destination, source, 0x0800, new byte[] { 0x45, 0, 0, 20, 0xAB, 0xCD, 0, 0, 1, 99, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 }, vlan).Serialize();

        BridgePort Access(Port port, ushort vlan = 1) => new(port, vlan, new HashSet<ushort> { vlan });
    }
    private sealed class Port(string name) : IPacketInterface
    {
        public string InterfaceName => name;
        public List<byte[]> Sent { get; } = [];
        public int Receive(byte[] buffer) => 0;
        public void Send(byte[] frame) => Sent.Add(frame);
        public void Dispose() { }
    }
}