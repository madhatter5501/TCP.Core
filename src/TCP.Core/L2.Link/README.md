# L2 — Link

Namespace `TCP.L2.Link`. Everything between raw frames and IP: the Ethernet frame
codec, ARP neighbor resolution and address claiming, and a separate VLAN-aware
learning bridge with spanning tree.

Two different things sit on top of this layer:

- **A host.** `EthernetStack` (in `src/TCP.Core/Stack`) plays L2 for one
  `IPacketInterface`: it filters frames addressed to it, dispatches by EtherType,
  answers and learns from ARP, claims its address before use, and implements
  `IIPv4Link` for the [network layer](../L3.Network/README.md) above.
- **A switch.** `LearningBridge` forwards frames between several interfaces. It
  runs no IP and is not part of `EthernetStack`.

## Layout

| Folder | Contents |
| --- | --- |
| `Ethernet/` | `EthernetFrame` (parse and serialize), `MacAddress`, `EtherType`, `EthernetConstants` |
| `Arp/` | `ArpPacket`, `ArpOperation`, `ArpCache` (the neighbor table), `ArpResolver` (queues datagrams while resolving), `ArpResponder` (answers requests for our address), `AddressClaim` (RFC 5227 probe, announce, defend) |
| `Bridge/` | `LearningBridge`, `BridgePort` (VLAN membership and tagging), `SpanningTree` (IEEE 802.1D), `BridgePortState` |

Every type carries XML documentation that explains its role and cites the
specification it follows; start with `EthernetFrame`, `ArpResolver` and
`LearningBridge`.

## Using it

A host needs only `EthernetStack`; it builds the ARP pieces itself:

```csharp
var stack = new EthernetStack(port, address, mac, new IPv4Subnet(address, mask));
stack.AddressClaimed += () => Console.WriteLine($"{address} is ours");
stack.NeighborResolutionFailed += neighbor => Console.WriteLine($"no ARP reply from {neighbor}");
stack.Run(cancellationToken); // probes the address first, then serves
```

A bridge takes two or more ports. Passing the bridge's own MAC address turns on
spanning tree, and each port's `HardwareAddress` becomes the source of its BPDUs;
without it, the topology must be loop-free.

```csharp
var ports = new[]
{
    new BridgePort(port1, Pvid: 1, Vlans: new HashSet<ushort> { 1 }, HardwareAddress: mac1),              // access port
    new BridgePort(port2, Pvid: 1, Vlans: new HashSet<ushort> { 1, 20 }, Trunk: true, HardwareAddress: mac2), // 802.1Q trunk
};
using var bridge = new LearningBridge(ports, spanningTreeAddress: bridgeMac);
bridge.Run(cancellationToken);
```

The codecs can also be used on their own, as `TCP.Host`'s diagnostics do:
`EthernetFrame.Parse(bytes)`, `ArpPacket.CreateRequest(...)`, `ArpResponder.TryCreateReply(...)`.

## Implemented

| Area | Behavior |
| --- | --- |
| Ethernet | Ethernet II and IEEE 802.3 LLC/SNAP (RFC 1042) decoded into one shape; a single 802.1Q tag (priority, drop eligibility, VLAN ID; VLAN 4095 rejected); padding to the 60-byte minimum; the host accepts only untagged or priority-tagged frames sent to its own MAC or to broadcast, from a valid unicast source other than itself |
| ARP | Requests and replies (RFC 826); sender MAC must match the frame source; a bounded cache (1,024 entries, one-minute expiry, the entry nearest expiry is replaced when full) |
| Resolution | Datagrams queue while ARP asks once a second, up to three times; at most 64 pending neighbors and 4 queued datagrams each (RFC 1122 2.3.2.2); failure raises `NeighborResolutionFailed`, and a silent gateway is avoided by routing for a while |
| Address claim | RFC 5227: three probes from 0.0.0.0, two announcements, then defense; a second conflict within 10 seconds gives the address up |
| Bridging | Per-VLAN MAC learning with five-minute ageing and 8,192 entries; flooding of unknown, broadcast and multicast destinations; access and trunk ports with tag insertion and removal; link-local 01-80-C2-00-00-0x control frames never forwarded |
| Spanning tree | IEEE 802.1D configuration and topology-change BPDUs, root and designated port election, blocking, listening, learning and forwarding states, default timers (hello 2 s, max age 20 s, forward delay 15 s) |

## Scope

This is a tested learning implementation, not a certified one. Not implemented:
jumbo frames, stacked (Q-in-Q) tags, proxy ARP, static ARP entries, RSTP and MSTP
(RSTP peers fall back to classic BPDUs), provider bridging and link aggregation.
The preamble and FCS belong to the network card; see [L1 — Physical](../L1.Physical/README.md).

`TCP.Host --bridge` does not enable spanning tree, so use a loop-free topology with it.

## Verification

```sh
dotnet run --project tests/TCP.Tests
```

`StandardsTests.cs` covers the Ethernet encapsulations, ARP expiry, resolution,
gateway next hops and address claiming. `BridgeTests.cs` covers learning, ageing,
flooding, VLAN isolation and control frames; `SpanningTreeTests.cs` covers 802.1D.
`Program.cs` checks the host's receive path (MAC filtering, ARP replies, conflict
probes). [docs/arp-cache.md](../../../docs/arp-cache.md) walks through the ARP
cache design in depth.

References: IEEE 802.3 (Ethernet), IEEE 802.1Q (VLANs), IEEE 802.1D (bridging and
spanning tree), [ARP (RFC 826)](https://www.rfc-editor.org/rfc/rfc826.html),
[IP over 802 networks (RFC 1042)](https://www.rfc-editor.org/rfc/rfc1042.html),
[IPv4 address conflict detection (RFC 5227)](https://www.rfc-editor.org/rfc/rfc5227.html).
