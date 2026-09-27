using System.Net;
using TCP.L2.Link.Arp;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Fragmentation;
using TCP.L3.Network.Icmp;

namespace TCP.Host;

internal static class ProtocolDiagnostics
{
    private const ushort EchoIdentifier = 1234;
    private const ushort PacketIdentification = 0x1234;
    private const byte IcmpProtocol = (byte)IPv4ProtocolNumber.Icmp;
    private const byte TcpProtocol = (byte)IPv4ProtocolNumber.Tcp;
    private const byte UdpProtocol = (byte)IPv4ProtocolNumber.Udp;
    private const int EchoRequestCount = 5;
    private const string StackAddressText = "10.0.0.1";
    private const string PeerAddressText = "10.0.0.2";
    private const string UnrelatedAddressText = "10.0.0.99";

    public static int Run()
    {
        RunArpRoundTrip();
        RunIpv4RoundTrip();
        RunProtocolDispatch();
        RunIcmpEchoRoundTrips();
        return 0;
    }

    private static void RunArpRoundTrip()
    {
        var stackMac = MacAddress.FromBytes([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB]);
        var peerMac = MacAddress.FromBytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        var stackAddress = IPAddress.Parse(StackAddressText);
        var peerAddress = IPAddress.Parse(PeerAddressText);

        var request = ArpPacket.CreateRequest(peerMac, peerAddress, stackAddress);
        var ethernetFrame = new EthernetFrame(MacAddress.Broadcast, peerMac, (ushort)EtherType.Arp, request.Serialize());
        var parsedRequest = ArpPacket.Parse(EthernetFrame.Parse(ethernetFrame.Serialize()).Payload.Span);

        Console.WriteLine($"Source MAC:      {peerMac}");
        Console.WriteLine($"Destination MAC: {MacAddress.Broadcast}");
        Console.WriteLine("EtherType:       ARP");
        Console.WriteLine($"Payload Length:  {parsedRequest.Serialize().Length}");
        Console.WriteLine($"Who has {parsedRequest.TargetProtocolAddress}?");
        Console.WriteLine($"Tell {parsedRequest.SenderProtocolAddress}");

        if (!ArpResponder.TryCreateReply(parsedRequest, stackAddress, stackMac, out var reply))
        {
            throw new InvalidOperationException("The stack did not answer an ARP request for its own address.");
        }

        var parsedReply = ArpPacket.Parse(reply.Serialize());
        var cache = new ArpCache();
        cache.Remember(parsedReply.SenderProtocolAddress, parsedReply.SenderHardwareAddress);
        if (!cache.TryResolve(stackAddress, out var resolvedMac) || resolvedMac != stackMac)
        {
            throw new InvalidOperationException("The ARP cache did not retain the learned address.");
        }

        Console.WriteLine($"{stackAddress} is at {resolvedMac}");

        var unrelatedRequest = ArpPacket.CreateRequest(peerMac, peerAddress, IPAddress.Parse(UnrelatedAddressText));
        if (ArpResponder.TryCreateReply(unrelatedRequest, stackAddress, stackMac, out _))
        {
            throw new InvalidOperationException("The stack answered an ARP request for another address.");
        }
    }

    private static void RunIpv4RoundTrip()
    {
        var stackAddress = IPAddress.Parse(StackAddressText);
        var peerAddress = IPAddress.Parse(PeerAddressText);
        var knownPacket = new byte[60];
        Convert.FromHexString("4500003C1C46400040069C5DC0A80001C0A800C7").CopyTo(knownPacket, 0);

        var parsedPacket = IPv4Packet.Parse(knownPacket);
        if (parsedPacket.SourceAddress.ToString() != "192.168.0.1" ||
            parsedPacket.DestinationAddress.ToString() != "192.168.0.199" ||
            parsedPacket.Protocol != TcpProtocol ||
            !parsedPacket.Serialize().AsSpan().SequenceEqual(knownPacket))
        {
            throw new InvalidOperationException("IPv4 parsing or serialization changed the known packet.");
        }

        var packetWithOptions = new IPv4Packet(
            0,
            PacketIdentification,
            IPv4FragmentField.DontFragmentFlag,
            IPv4Constants.DefaultTimeToLive,
            UdpProtocol,
            stackAddress,
            peerAddress,
            new byte[] { 1, 1, 1, 1 },
            new byte[] { 0xCA, 0xFE });
        var parsedOptionsPacket = IPv4Packet.Parse(packetWithOptions.Serialize());
        if (parsedOptionsPacket.HeaderLength != 24 ||
            !parsedOptionsPacket.Payload.Span.SequenceEqual(new byte[] { 0xCA, 0xFE }))
        {
            throw new InvalidOperationException("IPv4 options or payload were not preserved.");
        }

        ExpectArgumentException(() => IPv4Packet.Parse(knownPacket.AsSpan(0, 19)));

        var invalidChecksum = (byte[])knownPacket.Clone();
        invalidChecksum[10] ^= 1;
        ExpectArgumentException(() => IPv4Packet.Parse(invalidChecksum));
    }

    private static void RunProtocolDispatch()
    {
        var knownPacket = new byte[60];
        Convert.FromHexString("4500003C1C46400040069C5DC0A80001C0A800C7").CopyTo(knownPacket, 0);
        var packet = IPv4Packet.Parse(knownPacket);
        var handler = new DiagnosticProtocolHandler();

        foreach (var protocol in new[] { IcmpProtocol, TcpProtocol, UdpProtocol, (byte)99 })
        {
            var packetToDispatch = packet with { Protocol = protocol };
            IPv4ProtocolDispatcher.Dispatch(in packetToDispatch, handler);
        }

        if (handler.IcmpCount != 1 || handler.TcpCount != 1 || handler.UdpCount != 1 || handler.UnknownCount != 1)
        {
            throw new InvalidOperationException("IPv4 protocol numbers were routed to the wrong handlers.");
        }

        Console.WriteLine("IPv4 protocol dispatch: ICMP, TCP, UDP, unknown");
    }

    private static void RunIcmpEchoRoundTrips()
    {
        var stackAddress = IPAddress.Parse(StackAddressText);
        var peerAddress = IPAddress.Parse(PeerAddressText);

        for (ushort sequence = 1; sequence <= EchoRequestCount; sequence++)
        {
            var request = IcmpPacket.CreateEchoRequest(EchoIdentifier, sequence, new byte[] { 0xCA, 0xFE });
            var ipv4Request = new IPv4Packet(
                0,
                sequence,
                0,
                IPv4Constants.DefaultTimeToLive,
                IcmpProtocol,
                peerAddress,
                stackAddress,
                ReadOnlyMemory<byte>.Empty,
                request.Serialize());
            var parsedRequest = IPv4Packet.Parse(ipv4Request.Serialize());

            if (!IcmpEchoResponder.TryCreateReply(in parsedRequest, out var reply))
            {
                throw new InvalidOperationException("The stack did not answer an echo request.");
            }

            var parsedReply = IPv4Packet.Parse(reply.Serialize());
            var echoReply = IcmpPacket.Parse(parsedReply.Payload.Span);
            if (echoReply.Type != IcmpPacket.EchoReplyType || echoReply.Code != IcmpPacket.EchoCode ||
                echoReply.Identifier != EchoIdentifier || echoReply.SequenceNumber != sequence ||
                !echoReply.Payload.Span.SequenceEqual(request.Payload.Span) ||
                !parsedReply.SourceAddress.Equals(stackAddress) || !parsedReply.DestinationAddress.Equals(peerAddress))
            {
                throw new InvalidOperationException("The echo reply did not preserve the ping data or reverse its addresses.");
            }

            if (IcmpEchoResponder.TryCreateReply(in parsedReply, out _))
            {
                throw new InvalidOperationException("An echo reply incorrectly triggered another reply.");
            }
        }

        Console.WriteLine($"ICMP: {EchoRequestCount} echo requests answered; echo replies ignored");
    }

    private static void ExpectArgumentException(Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentException)
        {
            return;
        }

        throw new InvalidOperationException("The malformed packet was unexpectedly accepted.");
    }
}
