using System.Diagnostics;
using System.Net;
using TCP.L1.Physical;
using TCP.L2.Link.Arp;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.Icmp;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.Stack;
using TCP.Tests;

var local = IPAddress.Parse("172.16.10.250");
var peer = IPAddress.Parse("172.16.10.152");
var localMac = MacAddress.FromBytes([2, 0, 0, 0, 0, 1]);
var peerMac = MacAddress.FromBytes([2, 0, 0, 0, 0, 2]);
var otherMac = MacAddress.FromBytes([2, 0, 0, 0, 0, 3]);
var subnet = new IPv4Subnet(local, IPAddress.Parse("255.255.255.0"));
int passed = 0;

Test("malformed ICMP is dropped and the next valid ping is answered", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    server.ProcessFrame(Ping(payload: []));
    server.ProcessFrame(Ping(payload: [8, 0, 0, 0, 0, 0, 0, 0]));
    Check(port.Sent.Count == 0, "Malformed ICMP produced a reply");
    server.ProcessFrame(Arp(localMac, peer));
    port.Sent.Clear();
    server.ProcessFrame(Ping());
    Check(port.Sent.Count == 1, "Valid ping after malformed input failed");
    var frame = EthernetFrame.Parse(port.Sent[0]);
    var ip = IPv4Packet.Parse(frame.Payload.Span);
    var echo = IcmpPacket.Parse(ip.Payload.Span);
    Check(frame.Destination == peerMac && ip.DestinationAddress.Equals(peer) &&
          echo.Type == 0 && echo.Identifier == 42 && echo.SequenceNumber == 7 &&
          echo.Payload.Span.SequenceEqual(new byte[] { 1, 2, 3 }), "Reply contents changed");
});
Test("frames for another MAC neither respond nor learn", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    server.ProcessFrame(Arp(otherMac, peer));
    server.ProcessFrame(Ping(destination: otherMac));
    Check(port.Sent.Count == 0 && !server.TryResolveNeighbor(peer, out _), "Foreign frame reached local stack");
});
Test("broadcast and local unicast ARP still work", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    server.ProcessFrame(Arp(MacAddress.Broadcast, peer));
    server.ProcessFrame(Arp(localMac, peer));
    Check(port.Sent.Count == 2 && server.TryResolveNeighbor(peer, out var mac) && mac == peerMac, "ARP regression");
});
Test("ARP probes are answered without caching 0.0.0.0", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    server.ProcessFrame(Arp(MacAddress.Broadcast, IPAddress.Any));
    Check(port.Sent.Count == 1 && !server.TryResolveNeighbor(IPAddress.Any, out _), "ARP probe regression");
});
Test("off-subnet IP sources are not neighbors or implicit gateway routes", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    var remote = IPAddress.Parse("10.9.8.7");
    server.ProcessFrame(Ping(source: remote));
    Check(port.Sent.Count == 0 && !server.TryResolveNeighbor(remote, out _), "Remote host learned or answered without route");
    server.ProcessFrame(Arp(MacAddress.Broadcast, remote));
    Check(!server.TryResolveNeighbor(remote, out _), "Off-link ARP learned");
});
Test("invalid IPv4 sources are discarded before learning", () =>
{
    foreach (var text in new[] { "0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.1", "240.1.2.3", "255.255.255.255", "172.16.10.0", "172.16.10.255" })
    {
        var port = new FakePort(); using var server = Server(port);
        
        var source = IPAddress.Parse(text);
        server.ProcessFrame(Ping(source));
        Check(port.Sent.Count == 0 && !server.TryResolveNeighbor(source, out _), $"Accepted {text}");
    }
});
Test("invalid ARP advertisements cannot populate the cache", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    server.ProcessFrame(Arp(MacAddress.Broadcast, peer, otherMac));
    server.ProcessFrame(Arp(MacAddress.Broadcast, IPAddress.Broadcast));
    Check(port.Sent.Count == 0 && !server.TryResolveNeighbor(peer, out _) &&
          !server.TryResolveNeighbor(IPAddress.Broadcast, out _), "Invalid advertisement accepted");
});
Test("multicast and zero Ethernet sources are rejected", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    var frame = EthernetFrame.Parse(Ping());
    foreach (var source in new[] { default(MacAddress), MacAddress.Broadcast, MacAddress.FromBytes([1, 0, 0, 0, 0, 1]) })
        server.ProcessFrame((frame with { Source = source }).Serialize());
    Check(port.Sent.Count == 0 && !server.TryResolveNeighbor(peer, out _), "Invalid L2 source accepted");
});
Test("connected route and /31 host address rules", () =>
{
    Check(subnet.TryGetNextHop(peer, out var next) && next.Equals(peer), "Wrong connected next hop");
    Check(!subnet.TryGetNextHop(IPAddress.Parse("10.1.2.3"), out _), "Invented remote route");
    var pointToPoint = new IPv4Subnet(IPAddress.Parse("10.0.0.0"), IPAddress.Parse("255.255.255.254"));
    Check(pointToPoint.IsValidSource(IPAddress.Parse("10.0.0.0")) &&
          pointToPoint.IsValidSource(IPAddress.Parse("10.0.0.1")), "/31 endpoints rejected");
});
Test("quiet startup probing can be cancelled", () =>
{
    var port = new FakePort(); using var server = Server(port);
    
    using var cancel = new CancellationTokenSource(100);
    var timer = Stopwatch.StartNew();
    try { server.Run(cancel.Token); }
    catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
    Check(timer.Elapsed < TimeSpan.FromSeconds(2) && port.Sent.Count <= 1, "Probe cancellation stalled");
});
Test("quiet startup completes and the idle receive loop can be cancelled", () =>
{
    var time = new FakeTime();
    using var cancel = new CancellationTokenSource();
    var port = new FakePort { OnReceive = () => { time.Advance(TimeSpan.FromSeconds(1)); if (time.GetUtcNow().Second >= 15) cancel.Cancel(); } };
    using var server = new EthernetStack(port, local, localMac, subnet, time);
    server.Run(cancel.Token);
    Check(port.Sent.Count == 5, "Expected three probes and two announcements");
    Check(port.Receives < 30, "Idle loop is busy spinning");
});
passed += StandardsTests.Run();
passed += BridgeTests.Run();
passed += SpanningTreeTests.Run();
passed += TcpTests.Run();
passed += Http2Tests.Run();
passed += UdpTests.Run();
passed += TlsTests.Run();
Console.WriteLine($"{passed} regression tests passed.");
return;

void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

void Test(string name, Action body)
{
    body();
    passed++;
    Console.WriteLine($"PASS: {name}");
}

EthernetStack Server(FakePort port) => new(port, local, localMac, subnet);

byte[] Arp(MacAddress destination, IPAddress source, MacAddress? advertisedMac = null) =>
    new EthernetFrame(destination, peerMac, (ushort)EtherType.Arp,
        ArpPacket.CreateRequest(advertisedMac ?? peerMac, source, local).Serialize()).Serialize();

byte[] Ping(IPAddress? source = null, MacAddress? destination = null, byte[]? payload = null) =>
    new EthernetFrame(destination ?? localMac, peerMac, (ushort)EtherType.IPv4,
        new IPv4Packet(0, 123, 0, 64, 1, source ?? peer, local, ReadOnlyMemory<byte>.Empty,
            payload ?? IcmpPacket.CreateEchoRequest(42, 7, new byte[] { 1, 2, 3 }).Serialize()).Serialize()).Serialize();

namespace TCP.Tests
{
    internal sealed class FakePort : IPacketInterface
    {
        public string InterfaceName => "test0";
        public List<byte[]> Sent { get; } = [];
        public int Receives { get; private set; }
        public Action? OnReceive { get; init; }
        public int Receive(byte[] buffer) { Receives++; OnReceive?.Invoke(); return 0; }
        public void Send(byte[] frame) => Sent.Add(frame);
        public void Dispose() { }
    }

    internal sealed class FakeTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}