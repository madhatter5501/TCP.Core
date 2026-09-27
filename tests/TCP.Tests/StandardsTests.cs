using System.Buffers.Binary;
using System.Net;
using TCP.L2.Link.Arp;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.Icmp;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;
using TCP.L3.Network.IPv4.Options;
using TCP.L3.Network.IPv4.Routing;
using TCP.Stack;

namespace TCP.Tests;

internal static class StandardsTests
{
    public static int Run()
    {
        var count = 0;
        var local = IPAddress.Parse("172.16.10.250");
        var peer = IPAddress.Parse("172.16.10.152");
        var gateway = IPAddress.Parse("172.16.10.1");
        var remote = IPAddress.Parse("10.0.0.2");
        var mac = MacAddress.FromBytes([2, 0, 0, 0, 0, 1]);
        var peerMac = MacAddress.FromBytes([2, 0, 0, 0, 0, 2]);
        var subnet = new IPv4Subnet(local, IPAddress.Parse("255.255.255.0"));

        Test("ARP expires and evicts bounded entries", () =>
        {
            var time = new FakeTime(); var cache = new ArpCache(time, TimeSpan.FromSeconds(2), 1);
            cache.Remember(peer, peerMac); time.Advance(TimeSpan.FromSeconds(1)); cache.Remember(gateway, mac);
            Check(!cache.TryResolve(peer, out _) && cache.TryResolve(gateway, out _), "Cache eviction failed");
            time.Advance(TimeSpan.FromSeconds(2)); Check(cache.Count == 0, "Cache expiration failed");
        });
        Test("ARP resolution coalesces, retries, flushes and fails", () =>
        {
            var time = new FakeTime(); var requests = 0; var sent = 0; var failed = 0;
            var resolver = new ArpResolver(new ArpCache(time), _ => requests++, (_, _) => sent++, time);
            resolver.ResolutionFailed += _ => failed++;
            resolver.Send(peer, [1]); resolver.Send(peer, [2]);
            Check(requests == 1, "Duplicate ARP request");
            time.Advance(TimeSpan.FromSeconds(1)); resolver.Tick();
            resolver.Learned(peer, peerMac);
            Check(requests == 2 && sent == 2 && resolver.PendingCount == 0, "Pending packets not flushed");
            resolver.Send(gateway, [3]);
            for (var i = 0; i < 3; i++) { time.Advance(TimeSpan.FromSeconds(1)); resolver.Tick(); }
            Check(failed == 1 && requests == 5 && resolver.PendingCount == 0, "ARP retry budget failed");
        });
        Test("gateway ARP resolves next hop, never remote destination", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            host.IPv4.Routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), gateway, 1500));
            var p = Packet() with { SourceAddress = local, DestinationAddress = remote };
            Check(host.IPv4.SendIPv4(p), "Default route not selected");
            var request = ArpPacket.Parse(EthernetFrame.Parse(port.Sent.Single()).Payload.Span);
            Check(request.TargetProtocolAddress.Equals(gateway), "ARP requested remote host");
            var reply = ArpPacket.CreateReply(peerMac, gateway, mac, local);
            host.ProcessFrame(new EthernetFrame(mac, peerMac, (ushort)EtherType.Arp, reply.Serialize()).Serialize());
            Check(LastIp(port).DestinationAddress.Equals(remote), "Queued destination changed");
            Check(!host.TryResolveNeighbor(remote, out _), "Remote host was learned");
        });
        Test("longest prefix wins over default route", () =>
        {
            var routes = new IPv4RouteTable(subnet);
            routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), gateway, 1500));
            Check(routes.TryLookup(peer, out var hop, out _) && hop.Equals(peer), "Default overrides connected route");
            Check(routes.TryLookup(remote, out hop, out _) && hop.Equals(gateway), "Gateway route absent");
        });
        Test("fragmentation and out-of-order reassembly preserve payload", () =>
        {
            var p = Packet(payloadLength: 4000);
            var fragments = IPv4Fragmenter.Fragment(p, 600);
            Check(fragments.All(f => f.TotalLength <= 600), "MTU exceeded");
            Check(fragments.Take(fragments.Count - 1).All(f => f.Payload.Length % 8 == 0), "Unaligned fragment");
            var reassembly = new IPv4Reassembler(); IPv4Packet complete = default; var completed = 0;
            foreach (var f in fragments.Reverse())
                if (reassembly.TryAccept(IPv4Packet.Parse(f.Serialize()), false, out complete, out _)) completed++;
            Check(completed == 1 && complete.Payload.Span.SequenceEqual(p.Payload.Span), "Reassembly changed data");
        });
        Test("fragmented echo is delivered once and reply respects MTU", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet, mtu: 600);
            Learn(host, port, peer);
            var p = Packet(payloadLength: 3000);
            foreach (var f in IPv4Fragmenter.Fragment(p, 800).Reverse()) host.ProcessFrame(Frame(f));
            Check(port.Sent.Count > 1, "Large reply was not fragmented");
            var r = new IPv4Reassembler(); IPv4Packet reply = default; var completed = 0;
            foreach (var frame in port.Sent)
            {
                var ip = IPv4Packet.Parse(EthernetFrame.Parse(frame).Payload.Span);
                Check(ip.TotalLength <= 600, "Reply exceeds MTU");
                if (r.TryAccept(ip, false, out reply, out _)) completed++;
            }
            Check(completed == 1 && IcmpPacket.Parse(reply.Payload.Span).Type == 0 &&
                  reply.Payload.Length == p.Payload.Length, "Fragmented echo reply invalid");
        });
        Test("overlap is rejected and never dispatched", () =>
        {
            var r = new IPv4Reassembler(); var p = Packet(payloadLength: 32);
            Check(!r.TryAccept(p with { FlagsAndFragmentOffset = 0x2000, Payload = p.Payload[..16] }, false, out _, out _), "Premature completion");
            Check(!r.TryAccept(p with { FlagsAndFragmentOffset = 1, Payload = p.Payload[8..] }, false, out _, out _), "Overlapping fragments accepted");
            Check(!r.TryAccept(p with { FlagsAndFragmentOffset = 2, Payload = p.Payload[16..] }, false, out _, out _), "Rejected assembly revived");
        });
        Test("reassembly timeout generates ICMP time exceeded", () =>
        {
            var time = new FakeTime(); var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet, time);
            Learn(host, port, peer);
            var f = Packet() with { FlagsAndFragmentOffset = 0x2000, Payload = new byte[8] };
            host.ProcessFrame(Frame(f)); time.Advance(TimeSpan.FromSeconds(61));
            // Refresh the expired ARP entry before the reassembly timer sends its error.
            Learn(host, port, peer); host.Tick();
            var error = IcmpPacket.Parse(LastIp(port).Payload.Span);
            Check(error.Type == 11 && error.Code == 1, "Missing reassembly timeout error");
        });
        Test("DF prevents oversized local sends", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet, mtu: 576);
            var p = Packet(payloadLength: 1000) with { SourceAddress = local, DestinationAddress = peer, FlagsAndFragmentOffset = 0x4000 };
            Check(!host.IPv4.SendIPv4(p) && port.Sent.Count == 0, "DF was ignored");
        });
        Test("unknown protocol gets an exact ICMP quote", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer); var p = Packet(protocol: 99);
            host.ProcessFrame(Frame(p)); var error = IcmpPacket.Parse(LastIp(port).Payload.Span);
            Check(error.Type == 3 && error.Code == 2 && error.Payload.Span.SequenceEqual(p.Serialize().AsSpan(0, 28)), "Bad error quote");
        });
        Test("no ICMP error in response to a broadcast", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer); host.ProcessFrame(Frame(Packet(protocol: 99), true));
            host.ProcessFrame(Frame(Packet(protocol: 99) with { DestinationAddress = IPAddress.Parse("172.16.10.255") }));
            Check(port.Sent.Count == 0, "Broadcast triggered an error");
        });
        Test("malformed options get Parameter Problem with field pointer", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer); host.ProcessFrame(Frame(Packet() with { Options = new byte[] { 7, 0, 0, 0 } }));
            var error = IcmpPacket.Parse(LastIp(port).Payload.Span);
            Check(error.Type == 12 && error.RestOfHeader == (21u << 24), "Wrong parameter problem pointer");
        });
        Test("record route and timestamp options are processed", () =>
        {
            var p = Packet() with { Options = new byte[] { 7, 7, 4, 0, 0, 0, 0, 0 } };
            Check(IPv4Options.TryProcess(p, local, DateTimeOffset.UtcNow, out var updated, out _, out _), "Record route failed");
            Check(updated.Options.Span[2] == 8 && updated.Options.Span.Slice(3, 4).SequenceEqual(local.GetAddressBytes()), "Record route omitted local address");
            p = p with { Options = new byte[] { 68, 8, 5, 0, 0, 0, 0, 0 } };
            Check(IPv4Options.TryProcess(p, local, new DateTimeOffset(2026, 1, 1, 0, 0, 1, TimeSpan.Zero), out updated, out _, out _), "Timestamp failed");
            Check(BinaryPrimitives.ReadUInt32BigEndian(updated.Options.Span[4..]) == 1000, "Timestamp isn't UTC milliseconds");
        });
        Test("only copied options appear in later fragments", () =>
        {
            var p = Packet(payloadLength: 2000) with { Options = new byte[] { 7, 7, 4, 0, 0, 0, 0, 0 } };
            var f = IPv4Fragmenter.Fragment(p, 576);
            Check(f[0].Options.Length == 8 && f.Skip(1).All(v => v.Options.IsEmpty), "Noncopied options duplicated");
        });
        Test("host delivers TTL one without routing decrement", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            IPv4Packet? received = null; host.IPv4.RegisterProtocol(99, p => received = p);
            host.ProcessFrame(Frame(Packet(99) with { TimeToLive = 1 }));
            Check(received?.TimeToLive == 1, "Host treated local packet as forwarding");
        });
        Test("address claim probes, announces, defends, and abandons", () =>
        {
            var time = new FakeTime(); var sent = new List<ArpPacket>();
            var claim = new AddressClaim(local, mac, sent.Add, time, () => 0);
            claim.Tick();
            for (var i = 0; i < 6; i++) { time.Advance(TimeSpan.FromSeconds(1)); claim.Tick(); }
            Check(claim.Ready && sent.Count == 5 && sent.Take(3).All(p => p.SenderProtocolAddress.Equals(IPAddress.Any)), "Claim timing failed");
            var conflict = ArpPacket.CreateReply(peerMac, local, mac, local);
            claim.Observe(conflict); Check(sent.Count == 6, "Address wasn't defended");
            try { claim.Observe(conflict); throw new Exception("Conflict was ignored"); }
            catch (InvalidOperationException) { Check(!claim.Ready, "Conflicted address still active"); }
        });
        Test("competing ARP probe prevents address acquisition", () =>
        {
            var claim = new AddressClaim(local, mac, _ => { });
            try { claim.Observe(ArpPacket.CreateRequest(peerMac, IPAddress.Any, local)); throw new Exception("Probe conflict ignored"); }
            catch (InvalidOperationException) { }
        });
        Test("Ethernet padding, VLAN and LLC/SNAP round trip", () =>
        {
            var f = new EthernetFrame(mac, peerMac, (ushort)EtherType.IPv4, Packet().Serialize());
            Check(new EthernetFrame(mac, peerMac, (ushort)EtherType.Arp, new byte[28]).Serialize().Length == 60, "Missing minimum Ethernet padding");
            var vlan = EthernetFrame.Parse((f with { VlanTag = 123 }).Serialize());
            Check(vlan.VlanTag == 123 && vlan.EtherType == 0x800, "VLAN round trip failed");
            var snap = EthernetFrame.Parse((f with { UsesLlcSnap = true }).Serialize());
            Check(snap.UsesLlcSnap && snap.Payload.Span.SequenceEqual(f.Payload.Span), "SNAP length/padding failed");
        });
        Test("DF echo request is answered as a new datagram", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer); host.ProcessFrame(Frame(Packet() with { FlagsAndFragmentOffset = 0x4000 }));
            var reply = LastIp(port);
            Check(IcmpPacket.Parse(reply.Payload.Span).Type == 0 && (reply.FlagsAndFragmentOffset & 0x4000) == 0,
                "Echo request DF was incorrectly inherited");
        });
        Test("completed source route is reversed for echo reply", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, gateway);
            var p = Packet() with { SourceAddress = remote, Options = new byte[] { 131, 7, 8, 172, 16, 10, 1, 0 } };
            host.ProcessFrame(Frame(p));
            var reply = LastIp(port);
            Check(reply.DestinationAddress.Equals(gateway) && reply.Options.Span[2] == 4 &&
                  new IPAddress(reply.Options.Span.Slice(3, 4)).Equals(remote), "Source route reversal failed");
        });
        Test("incomplete source routes are not forwarded by the host", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer);
            host.ProcessFrame(Frame(Packet() with { Options = new byte[] { 131, 7, 4, 172, 16, 10, 1, 0 } }));
            var error = IcmpPacket.Parse(LastIp(port).Payload.Span);
            Check(error.Type == 3 && error.Code == 5, "Host forwarded an incomplete source route");
        });
        Test("redirects require the current gateway and expire", () =>
        {
            var time = new FakeTime(); var routes = new IPv4RouteTable(subnet, timeProvider: time);
            routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), gateway, 1500));
            Check(!routes.ApplyRedirect(peer, remote, peer), "Non-gateway redirect accepted");
            Check(!routes.ApplyRedirect(gateway, remote, remote), "Off-link redirect accepted");
            Check(routes.ApplyRedirect(gateway, remote, peer), "Valid redirect rejected");
            Check(routes.TryLookup(remote, out var hop, out _) && hop.Equals(peer), "Redirect not used");
            time.Advance(TimeSpan.FromMinutes(11));
            Check(routes.TryLookup(remote, out hop, out _) && hop.Equals(gateway), "Redirect didn't expire");
        });
        Test("ARP failure allows another default gateway", () =>
        {
            var routes = new IPv4RouteTable(subnet);
            routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), gateway, 1500));
            routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), peer, 1500, 1));
            routes.MarkUnreachable(gateway);
            Check(routes.TryLookup(remote, out var hop, out _) && hop.Equals(peer), "Failed gateway remained selected");
        });
        Test("received ICMP errors are delivered only for recently sent datagrams", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer); var received = 0; host.IPv4.IcmpErrorReceived += (_, _) => received++;
            host.IPv4.SendIPv4(Packet() with { SourceAddress = local, DestinationAddress = peer });
            var sent = LastIp(port).Serialize();
            var error = new IcmpPacket(3, 4, 576, sent.AsMemory(0, 28));
            host.ProcessFrame(Frame(Packet() with { Payload = error.Serialize() }));
            Check(received == 1, "Valid error not delivered");
            var unrelated = Packet() with { SourceAddress = local, DestinationAddress = remote };
            error = error with { Payload = unrelated.Serialize().AsMemory(0, 28) };
            host.ProcessFrame(Frame(Packet() with { Payload = error.Serialize() }));
            Check(received == 1, "Unrelated quoted packet accepted");
        });
        Test("ICMP errors never trigger another ICMP error", () =>
        {
            var port = new FakePort(); using var host = new EthernetStack(port, local, mac, subnet);
            Learn(host, port, peer);
            var error = new IcmpPacket(3, 1, 0, new byte[28]);
            host.ProcessFrame(Frame(Packet() with { Payload = error.Serialize(), Options = new byte[] { 7, 0, 0, 0 } }));
            Check(port.Sent.Count == 0, "ICMP error loop");
        });
        Test("duplicate fragments do not duplicate completion", () =>
        {
            var r = new IPv4Reassembler(); var p = Packet(payloadLength: 1000); var fragments = IPv4Fragmenter.Fragment(p, 600);
            Check(!r.TryAccept(fragments[0], false, out _, out _), "Premature completion");
            Check(!r.TryAccept(fragments[0], false, out _, out _), "Duplicate fragment completed packet");
            Check(r.TryAccept(fragments[1], false, out var result, out _) && result.Payload.Span.SequenceEqual(p.Payload.Span), "Duplicate disrupted reassembly");
        });
        return count;

        void Check(bool value, string message) { if (!value) throw new Exception(message); }

        void Test(string name, Action action) { action(); count++; Console.WriteLine("PASS: " + name); }

        IPv4Packet Packet(byte protocol = 1, int payloadLength = 32) => new(0, 73, 0, 64, protocol, peer, local,
            ReadOnlyMemory<byte>.Empty, IcmpPacket.CreateEchoRequest(5, 6, new byte[payloadLength]).Serialize());

        byte[] Frame(IPv4Packet p, bool broadcast = false) => new EthernetFrame(broadcast ? MacAddress.Broadcast : mac,
            peerMac, (ushort)EtherType.IPv4, p.Serialize()).Serialize();

        void Learn(EthernetStack host, FakePort port, IPAddress address)
        {
            var arp = ArpPacket.CreateReply(peerMac, address, mac, local);
            host.ProcessFrame(new EthernetFrame(mac, peerMac, (ushort)EtherType.Arp, arp.Serialize()).Serialize());
            port.Sent.Clear();
        }

        IPv4Packet LastIp(FakePort port) => IPv4Packet.Parse(EthernetFrame.Parse(port.Sent.Last()).Payload.Span);
    }
}