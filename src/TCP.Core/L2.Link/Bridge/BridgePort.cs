using TCP.L1.Physical;
using TCP.L2.Link.Ethernet;

namespace TCP.L2.Link.Bridge;

/// <summary>Port VLAN membership and tagging. A trunk tags all egress frames; an access port uses its PVID.</summary>
/// <param name="Interface">The Ethernet interface behind this port.</param>
/// <param name="Pvid">Port VLAN ID: the VLAN assigned to untagged frames arriving here.</param>
/// <param name="Vlans">The VLANs this port belongs to; exactly one for an access port.</param>
/// <param name="Trunk">Carries several VLANs with 802.1Q tags, rather than one untagged VLAN.</param>
/// <param name="MaximumFrameLength">Largest frame accepted or sent, without FCS; 1518 fits a tagged 1500-byte payload.</param>
/// <param name="HardwareAddress">The port's own MAC address, used as the source of its spanning tree BPDUs.</param>
public sealed record BridgePort(IPacketInterface Interface, ushort Pvid, IReadOnlySet<ushort> Vlans,
    bool Trunk = false, int MaximumFrameLength = 1518, MacAddress HardwareAddress = default);