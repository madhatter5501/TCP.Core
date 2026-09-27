using System.Net;
using TCP.L3.Network;
using TCP.L3.Network.Icmp;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.L4.Transport.Udp;

namespace TCP.Tests;

/// <summary>Regression tests for UDP: the codec, port demultiplexing, ICMP reporting, broadcast and fragmentation.</summary>
internal static class UdpTests
{
    public static int Run()
    {
        var passed = 0;
        Test("codec matches an independent checksum fixture and validates length and checksum", () =>
        {
            var a = IPAddress.Parse("192.0.2.1"); var b = IPAddress.Parse("192.0.2.2");
            var fixture = Convert.FromHexString("30390035000b8703616263");
            var datagram = new UdpDatagram(12345, 53, "abc"u8.ToArray());
            Check(datagram.Serialize(a, b).SequenceEqual(fixture), "Checksum fixture mismatch");
            var parsed = UdpDatagram.Parse(a, b, fixture);
            Check(parsed.SourcePort == 12345 && parsed.DestinationPort == 53 && parsed.Payload.Span.SequenceEqual("abc"u8), "Parse mismatch");
            Check(UdpDatagram.Parse(a, b, [.. fixture, 0, 0]).Payload.Length == 3, "Trailing padding not ignored");
            var unchecked_ = (byte[])fixture.Clone(); unchecked_[6] = unchecked_[7] = 0;
            Check(UdpDatagram.Parse(a, b, unchecked_).Payload.Length == 3, "Zero (absent) IPv4 checksum rejected");
            var corrupt = (byte[])fixture.Clone(); corrupt[^1] ^= 1; Throws(() => UdpDatagram.Parse(a, b, corrupt));
            Throws(() => UdpDatagram.Parse(a, IPAddress.Parse("192.0.2.3"), fixture));
            Throws(() => UdpDatagram.Parse(a, b, fixture[..7]));
            var truncated = (byte[])fixture.Clone(); truncated[5] = 20; Throws(() => UdpDatagram.Parse(a, b, truncated));
            var v6a = IPAddress.Parse("2001:db8::1"); var v6b = IPAddress.Parse("2001:db8::2");
            var v6 = datagram.Serialize(v6a, v6b);
            Check(UdpDatagram.Parse(v6a, v6b, v6).Payload.Length == 3, "IPv6 checksum failed");
            v6[6] = v6[7] = 0; Throws(() => UdpDatagram.Parse(v6a, v6b, v6));
        });
        Test("datagrams reach the bound port with boundaries preserved and replies return", () =>
        {
            var n = new Network(); using var server = n.UdpB.Bind(53); using var client = n.UdpA.Bind();
            var received = new List<UdpReceivedDatagram>();
            server.Received += (socket, datagram) => { received.Add(datagram); socket.SendTo(datagram.RemoteAddress, datagram.RemotePort, datagram.Payload.Span); };
            var replies = new List<string>(); client.Received += (_, d) => replies.Add(System.Text.Encoding.ASCII.GetString(d.Payload.Span));
            Check(client.LocalPort >= 49152, "Ephemeral port outside the dynamic range");
            client.SendTo(n.B.LocalAddress, 53, "one"u8); client.SendTo(n.B.LocalAddress, 53, "two"u8); n.Pump();
            Check(received.Count == 2 && received.All(d => d.RemotePort == client.LocalPort && !d.Broadcast), "Datagrams not delivered separately");
            Check(replies.SequenceEqual(["one", "two"]), "Replies lost or merged");
        });
        Test("an unbound port answers ICMP port unreachable, which reaches the sending socket", () =>
        {
            var n = new Network(); using var client = n.UdpA.Bind(); var errors = new List<UdpError>();
            client.ErrorReceived += (_, error) => errors.Add(error);
            client.SendTo(n.B.LocalAddress, 9999, "anyone?"u8); n.Pump();
            Check(errors.Count == 1 && errors[0].IcmpType == (byte)IcmpMessageType.DestinationUnreachable &&
                  errors[0].IcmpCode == (byte)IcmpDestinationUnreachableCode.PortUnreachable &&
                  errors[0].RemotePort == 9999 && errors[0].RemoteAddress.Equals(n.B.LocalAddress), "Port unreachable not reported");
            var corrupt = new UdpDatagram(client.LocalPort, 9999, "x"u8.ToArray()).Serialize(n.A.LocalAddress, n.B.LocalAddress); corrupt[^1] ^= 1;
            n.B.Receive(new IPv4Packet(0, 7, 0, 64, 17, n.A.LocalAddress, n.B.LocalAddress, default, corrupt).Serialize(), false);
            Check(n.Queue.Count == 0, "Corrupt datagram drew a reply");
        });
        Test("broadcast needs EnableBroadcast and reaches listeners without drawing errors", () =>
        {
            var n = new Network(); using var listener = n.UdpB.Bind(67); using var sender = n.UdpA.Bind(68);
            var got = new List<UdpReceivedDatagram>(); listener.Received += (_, d) => got.Add(d);
            var broadcast = IPAddress.Parse("192.0.2.255");
            ThrowsInvalid(() => sender.SendTo(broadcast, 67, "discover"u8));
            sender.EnableBroadcast = true; sender.SendTo(broadcast, 67, "discover"u8); n.Pump();
            Check(got.Count == 1 && got[0].Broadcast, "Broadcast not delivered");
            sender.SendTo(broadcast, 999, "nobody"u8); n.Pump(); Check(n.History.Count(p => p.Protocol == 1) == 0, "Broadcast drew ICMP");
        });
        Test("a connected socket filters other senders and sends to its peer", () =>
        {
            var n = new Network(); using var server = n.UdpB.Bind(123); using var peer = n.UdpA.Bind(1000); using var stranger = n.UdpA.Bind(1001);
            var got = new List<ushort>(); server.Received += (_, d) => got.Add(d.RemotePort);
            ThrowsInvalid(() => server.Send("x"u8));
            server.Connect(n.A.LocalAddress, 1000);
            peer.SendTo(n.B.LocalAddress, 123, "a"u8); stranger.SendTo(n.B.LocalAddress, 123, "b"u8); n.Pump();
            Check(got.SequenceEqual(new ushort[] { 1000 }), "Connected socket accepted a stranger");
            var back = 0; peer.Received += (_, _) => back++; server.Send("reply"u8); n.Pump(); Check(back == 1, "Connected send failed");
        });
        Test("large datagrams are fragmented by IPv4 and reassembled whole", () =>
        {
            var n = new Network(); using var receiver = n.UdpB.Bind(5000); using var sender = n.UdpA.Bind();
            byte[]? got = null; receiver.Received += (_, d) => got = d.Payload.ToArray();
            var data = new byte[4000]; Random.Shared.NextBytes(data);
            sender.SendTo(n.B.LocalAddress, 5000, data);
            var fragments = n.A.FragmentForTransmit(n.Queue.Single().Packet).ToArray();
            Check(fragments.Length == 3 && fragments.All(p => p.TotalLength <= 1500), "Datagram not fragmented to the MTU");
            n.Pump(); Check(got is not null && got.SequenceEqual(data), "Fragmented datagram not reassembled");
            Throws(() => sender.SendTo(n.B.LocalAddress, 5000, new byte[UdpDatagram.MaximumIPv4PayloadLength + 1]));
        });
        Test("ports are exclusive until the socket is disposed", () =>
        {
            var n = new Network(); var first = n.UdpA.Bind(4000);
            ThrowsInvalid(() => n.UdpA.Bind(4000));
            first.Dispose(); using var second = n.UdpA.Bind(4000);
            Check(n.UdpA.Sockets.Single() == second, "Port not released on dispose");
            first.Dispose(); Check(n.UdpA.Sockets.Count == 1, "Second dispose released another socket's port");
        });
        return passed;

        void Test(string name, Action body) { body(); passed++; Console.WriteLine($"PASS: UDP {name}"); }
    }

    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }

    private static void Throws(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new Exception("Expected validation failure");
    }

    private static void ThrowsInvalid(Action action)
    {
        try { action(); } catch (InvalidOperationException) { return; }
        throw new Exception("Expected invalid operation");
    }

    /// <summary>Delivers unicast to the neighbor and broadcasts to it with the link-broadcast flag.</summary>
    private sealed class Link(Action<IPv4Packet, bool> send) : IIPv4Link
    {
        public bool IsReady => true;
        public void SendBroadcast(IPv4Packet packet) => send(packet, true);
        public void SendToNeighbor(IPAddress nextHop, IPv4Packet packet) => send(packet, false);
    }

    /// <summary>Two IPv4 hosts with UDP on one subnet, joined by a queue the test pumps.</summary>
    private sealed class Network
    {
        public readonly FakeTime Clock = new();
        public readonly Queue<(bool FromA, IPv4Packet Packet, bool Broadcast)> Queue = new();
        public readonly List<IPv4Packet> History = [];
        public readonly IPv4Host A, B;
        public readonly UdpHost UdpA, UdpB;

        public Network(int mtu = 1500)
        {
            var a = IPAddress.Parse("192.0.2.1"); var b = IPAddress.Parse("192.0.2.2"); var subnet = new IPv4Subnet(a, IPAddress.Parse("255.255.255.0"));
            A = new(new Link((p, broadcast) => { Queue.Enqueue((true, p, broadcast)); History.Add(p); }), a, subnet, Clock, mtu);
            B = new(new Link((p, broadcast) => { Queue.Enqueue((false, p, broadcast)); History.Add(p); }), b, subnet, Clock, mtu);
            UdpA = new(A); UdpB = new(B);
        }

        public void Pump()
        {
            for (var count = 0; Queue.TryDequeue(out var item); count++)
            {
                if (count > 10000) throw new Exception("Packet loop");
                // Fragments come from the link one by one, as the Ethernet layer would deliver them.
                foreach (var fragment in (item.FromA ? A : B).FragmentForTransmit(item.Packet))
                    (item.FromA ? B : A).Receive(fragment.Serialize(), item.Broadcast);
            }
        }
    }
}
