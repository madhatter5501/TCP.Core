namespace TCP.L2.Link.Ethernet;

/// <summary>
/// Values of the Ethernet type field, naming what a frame carries (IEEE registry). Values of 1536 (0x0600) and up
/// are types; 1500 and below are 802.3 lengths instead.
/// </summary>
public enum EtherType : ushort
{
    /// <summary>An IPv4 datagram.</summary>
    IPv4 = 0x0800,
    /// <summary>An ARP packet, resolving IPv4 addresses to MAC addresses.</summary>
    Arp = 0x0806,
    /// <summary>An 802.1Q VLAN tag follows; the real type comes after it.</summary>
    VlanTag = 0x8100,
    /// <summary>An 802.1ad (Q-in-Q) service tag, used by provider bridges; this stack drops such frames.</summary>
    ProviderVlanTag = 0x88A8,
    /// <summary>An IPv6 datagram; recognized but not handled by this stack.</summary>
    IPv6 = 0x86DD
}