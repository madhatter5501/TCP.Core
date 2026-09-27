using TCP.L2.Link.Ethernet;
using TCP.L3.Network.IPv4;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>What the virtual link saw in one frame, recorded before any injected fault.</summary>
internal sealed record FrameInfo(bool FromServer, bool IsTcp, TcpFlags Flags, int PayloadLength, ushort Window, int IPv4Length,
    uint Sequence = 0, uint Acknowledgment = 0)
{
    public static FrameInfo Parse(bool fromServer, byte[] frame)
    {
        try
        {
            var ethernet = EthernetFrame.Parse(frame);
            if (ethernet.EtherType != (ushort)EtherType.IPv4) return new FrameInfo(fromServer, false, TcpFlags.None, 0, 0, 0);
            var ip = IPv4Packet.Parse(ethernet.Payload.Span);
            if (ip.Protocol != (byte)IPv4ProtocolNumber.Tcp) return new FrameInfo(fromServer, false, TcpFlags.None, 0, 0, ip.TotalLength);
            var tcp = TcpSegment.Parse(ip.SourceAddress, ip.DestinationAddress, ip.Payload.Span);
            return new FrameInfo(fromServer, true, tcp.Flags, tcp.Payload.Length, tcp.Window, ip.TotalLength, tcp.SequenceNumber, tcp.AcknowledgmentNumber);
        }
        catch (ArgumentException)
        {
            return new FrameInfo(fromServer, false, TcpFlags.None, 0, 0, 0);
        }
    }

    public override string ToString() =>
        $"{(FromServer ? "S>C" : "C>S")} {(IsTcp ? $"{Flags} seq={Sequence} ack={Acknowledgment} len={PayloadLength} win={Window}" : "non-TCP")}";
}
