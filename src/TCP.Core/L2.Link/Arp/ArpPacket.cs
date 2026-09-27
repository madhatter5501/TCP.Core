using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Arp;

/// <summary>An ARP packet for Ethernet/IPv4. Ethernet padding is not part of the packet.</summary>
/// <remarks>
/// ARP (RFC 826) is the glue between L3 and L2. IP knows a neighbor's IPv4 address but Ethernet needs its MAC
/// address, so a host broadcasts "who has 192.0.2.7?" and the owner replies with its MAC. Every packet also states
/// the sender's own mapping, which lets receivers refresh their caches. The format is generic, but this codec
/// accepts only the Ethernet-hardware and IPv4-protocol form, which is 28 bytes.
/// </remarks>
/// <param name="Operation">Request or reply.</param>
/// <param name="SenderHardwareAddress">The sender's MAC address.</param>
/// <param name="SenderProtocolAddress">The sender's IPv4 address; 0.0.0.0 in an address-conflict probe.</param>
/// <param name="TargetHardwareAddress">The target's MAC address; zero in a request, because that is what is being asked.</param>
/// <param name="TargetProtocolAddress">The IPv4 address being asked about, or the requester's address in a reply.</param>
public readonly record struct ArpPacket(
    ArpOperation Operation,
    MacAddress SenderHardwareAddress,
    IPAddress SenderProtocolAddress,
    MacAddress TargetHardwareAddress,
    IPAddress TargetProtocolAddress)
{
    private const int PacketLength = 28;
    private const int HardwareTypeOffset = 0;
    private const int ProtocolTypeOffset = 2;
    private const int HardwareAddressLengthOffset = 4;
    private const int ProtocolAddressLengthOffset = 5;
    private const int OperationOffset = 6;
    private const int SenderHardwareAddressOffset = 8;
    private const int SenderProtocolAddressOffset = 14;
    private const int TargetHardwareAddressOffset = 18;
    private const int TargetProtocolAddressOffset = 24;
    private const int HardwareAddressLength = EthernetConstants.MacAddressLength;
    private const int IPv4AddressLength = 4;
    private const ushort EthernetHardwareType = 1;
    private const ushort IPv4EtherType = (ushort)EtherType.IPv4;

    /// <summary>Decodes an Ethernet frame's ARP payload. Trailing Ethernet padding is ignored.</summary>
    /// <exception cref="ArgumentException">Too short, or not the Ethernet/IPv4 form of ARP.</exception>
    public static ArpPacket Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < PacketLength)
        {
            throw new ArgumentException(
                $"An Ethernet/IPv4 ARP packet must contain at least {PacketLength} bytes.",
                nameof(bytes));
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(HardwareTypeOffset, sizeof(ushort))) != EthernetHardwareType ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(ProtocolTypeOffset, sizeof(ushort))) != IPv4EtherType ||
            bytes[HardwareAddressLengthOffset] != HardwareAddressLength ||
            bytes[ProtocolAddressLengthOffset] != IPv4AddressLength)
        {
            throw new ArgumentException(
                "The ARP packet must use Ethernet hardware addresses and IPv4 protocol addresses.",
                nameof(bytes));
        }

        return new ArpPacket(
            (ArpOperation)BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(OperationOffset, sizeof(ushort))),
            MacAddress.FromBytes(bytes.Slice(SenderHardwareAddressOffset, HardwareAddressLength)),
            new IPAddress(bytes.Slice(SenderProtocolAddressOffset, IPv4AddressLength)),
            MacAddress.FromBytes(bytes.Slice(TargetHardwareAddressOffset, HardwareAddressLength)),
            new IPAddress(bytes.Slice(TargetProtocolAddressOffset, IPv4AddressLength)));
    }

    /// <summary>Encodes the 28-byte packet with the Ethernet hardware type and the IPv4 protocol type.</summary>
    /// <exception cref="ArgumentException">A protocol address is not IPv4.</exception>
    public byte[] Serialize()
    {
        var bytes = new byte[PacketLength];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(HardwareTypeOffset, sizeof(ushort)), EthernetHardwareType);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(ProtocolTypeOffset, sizeof(ushort)), IPv4EtherType);
        bytes[HardwareAddressLengthOffset] = HardwareAddressLength;
        bytes[ProtocolAddressLengthOffset] = IPv4AddressLength;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(OperationOffset, sizeof(ushort)), (ushort)Operation);
        SenderHardwareAddress.WriteBytes(bytes.AsSpan(SenderHardwareAddressOffset, HardwareAddressLength));
        WriteIPv4Address(
            SenderProtocolAddress,
            bytes.AsSpan(SenderProtocolAddressOffset, IPv4AddressLength),
            nameof(SenderProtocolAddress));
        TargetHardwareAddress.WriteBytes(bytes.AsSpan(TargetHardwareAddressOffset, HardwareAddressLength));
        WriteIPv4Address(
            TargetProtocolAddress,
            bytes.AsSpan(TargetProtocolAddressOffset, IPv4AddressLength),
            nameof(TargetProtocolAddress));
        return bytes;
    }

    /// <summary>
    /// A request asking who owns <paramref name="targetIp"/>. With <paramref name="senderIp"/> equal to the target
    /// it becomes a gratuitous ARP announcement.
    /// </summary>
    public static ArpPacket CreateRequest(MacAddress senderMac, IPAddress senderIp, IPAddress targetIp) =>
        new(ArpOperation.Request, senderMac, senderIp, default, targetIp);

    /// <summary>A reply telling the requester (the target) that <paramref name="senderIp"/> is at <paramref name="senderMac"/>.</summary>
    public static ArpPacket CreateReply(
        MacAddress senderMac,
        IPAddress senderIp,
        MacAddress targetMac,
        IPAddress targetIp) =>
        new(ArpOperation.Reply, senderMac, senderIp, targetMac, targetIp);

    /// <summary>Writes a 4-byte protocol address, rejecting null or IPv6 addresses with an error naming the field.</summary>
    private static void WriteIPv4Address(IPAddress address, Span<byte> destination, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(address, parameterName);
        if (address.AddressFamily != AddressFamily.InterNetwork ||
            !address.TryWriteBytes(destination, out var written) || written != IPv4AddressLength)
        {
            throw new ArgumentException("ARP Ethernet packets require IPv4 protocol addresses.", parameterName);
        }
    }
}
