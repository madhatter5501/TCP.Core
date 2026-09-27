namespace TCP.L2.Link.Arp;

/// <summary>The ARP opcode (RFC 826).</summary>
public enum ArpOperation : ushort
{
    /// <summary>"Who has this IPv4 address?" Broadcast to the whole link.</summary>
    Request = 1,
    /// <summary>"I have it; here is my MAC address." Sent directly to the requester.</summary>
    Reply = 2
}