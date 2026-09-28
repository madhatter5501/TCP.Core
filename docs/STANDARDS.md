# Protocol scope

This project is a learning implementation, not a complete or certified network
stack. Successful ping tests and regression checks do not establish standards
compliance, and interoperability with real operating systems and NICs has not been
validated by the test suites.

Each layer's code lives under `src/TCP.Core` in a folder named for it (`L1.Physical`,
`L2.Link`, `L3.Network`, `L4.Transport`, `L5_7.Application`). Every type carries XML
documentation that explains its role in the stack and cites the specification it
follows.

| Area | Implemented | Remaining scope |
| --- | --- | --- |
| Physical (L1) | `IPacketInterface`: whole frames in and out, non-blocking receive; libpcap and in-memory virtual implementations | Preamble, FCS and signalling belong to the NIC and driver |
| Ethernet | Ethernet II and IEEE 802.3 LLC/SNAP (RFC 1042) encapsulation, a single 802.1Q tag, padding to the 60-byte minimum, host filtering of frames not addressed to it | Jumbo frames, stacked (Q-in-Q) tags; the host stack attaches only to untagged or priority-tagged traffic |
| Bridging | VLAN-aware learning bridge (IEEE 802.1Q access and trunk ports), per-VLAN MAC learning with five-minute ageing and a bounded table, flooding of unknown and group destinations, link-local 01-80-C2-00-00-0x groups never forwarded, classic spanning tree (IEEE 802.1D) with topology-change handling | RSTP and MSTP (RSTP peers fall back to classic BPDUs), provider bridging, link aggregation |
| ARP | Requests and replies (RFC 826), a bounded expiring neighbor cache, resolution with retries and per-neighbor packet queues, address-conflict probing, announcement and defense (RFC 5227) | Proxy ARP, static entries |
| IPv4 | Header validation, fragmentation and bounded, overlap-rejecting reassembly (with ECN combination, RFC 3168 5.3), Record Route, Internet Timestamp and source-route options, a route table with static routes, longest-prefix match, ICMP redirects and dead-gateway avoidance, Identification allocation (RFC 6864), a 576-byte off-subnet send cap | Router forwarding (RFC 1812), multicast group membership and IGMP, DHCP, IPv6 |
| ICMPv4 | Echo; Destination Unreachable (protocol, port, fragmentation needed, source route failed); Time Exceeded for reassembly; Parameter Problem with a pointer; Redirects received; errors rate-limited and never sent about broadcasts, non-first fragments or other errors (RFC 1122 3.2.2); received errors believed only if they quote a recent send | Router-generated messages such as TTL-expired in transit |
| TCP | RFC 9293 endpoint with window scaling, timestamps and PAWS, SACK and D-SACK, RACK-TLP, ECN, CUBIC or NewReno, delayed ACKs, SYN cookies, Fast Open, keep-alive, user timeout, TCP-AO and MD5, path-MTU black-hole detection | IPv6, Multipath TCP, AccECN, BBR; see the transport guide |
| UDP | RFC 768 sockets with ICMP port-unreachable, broadcast and connected-socket semantics | See the transport guide |
| Application (L5–7) | HTTP/2 frame codec (RFC 9113); TLS 1.3 and 1.2 client and server (RFC 8446, RFC 5246) over `TcpConnection` | HPACK (header blocks stay opaque) and stream state; TLS session resumption, 0-RTT and client certificates; see the [TLS guide](../src/TCP.Core/L5_7.Application/Tls/README.md) |

Ethernet is specified by IEEE 802.3; bridging and VLANs by IEEE 802.1D and 802.1Q.
Relevant Internet specifications include RFC 826 (ARP), RFC 791 (IPv4), RFC 792
(ICMP), RFC 1122 (host requirements), RFC 1191 (path MTU), RFC 5227 (IPv4 address
conflict detection), RFC 768 (UDP) and RFC 9293 (TCP), together with their updates.

`EthernetStack` is a single-interface host: it never forwards IP datagrams between
interfaces. `LearningBridge` is a separate L2 component that switches frames between
several interfaces and does not run IP. Off-subnet destinations are reached through a
configured gateway route; the host never infers a gateway from an incoming frame's
source MAC address.

## MTU versus MSS

- **MTU crosses the L2/L3 boundary:** a link's IP MTU limits the complete IP packet
  it can carry without fragmentation, including the IP header. Standard Ethernet
  carries a 1,500-byte IP packet; the Ethernet header and FCS are outside that
  number. IPv4 respects the outgoing link's MTU and the Don't Fragment flag when
  deciding whether to fragment or report an error.
- **MSS belongs to L4 (TCP):** the Maximum Segment Size option advertises the most
  TCP data a peer will accept in one segment. It excludes the IP and TCP headers.
  MSS negotiation and segmentation are implemented in `L4.Transport/Tcp`, including
  route limits, validated ICMP fragmentation-needed feedback, and black-hole
  detection when no ICMP arrives.

For IPv4/TCP with no IP or TCP options:

```text
1,500-byte IP MTU - 20-byte IPv4 header - 20-byte TCP header = 1,460-byte MSS
```

Actual TCP data per packet may be smaller because of options (timestamps alone take
12 bytes per segment), the peer's advertised MSS, or a smaller path MTU;
`TcpConnection.MaximumSegmentSize` accounts for all three. A pure L2 switch has
frame-size limits but does not fragment IP or negotiate TCP MSS.

## Transport and application layers

`EthernetStack.Tcp` and `EthernetStack.Udp` provide the transport layer; both run
their timers from `IPv4Host.Tick` through the existing stack loop. The Explorer
executes real TCP exchanges over its virtual Ethernet link, and
`TCP.Transport.Kestrel` runs ASP.NET Core over this TCP implementation. For TCP and
UDP behavior, settings, threading contract, API and remaining scope, see
[the transport guide](../src/TCP.Core/L4.Transport/README.md).
