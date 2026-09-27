/**
 * Layer-by-layer teaching content. It describes the checked-in TCP.Core source, not the RFCs in general,
 * so keep it in step with the implementation. File paths are relative to src/TCP.Core/.
 */

export type LayerSlug = 'application' | 'transport' | 'network' | 'link' | 'physical';

export interface HeaderField { name: string; bits: string; purpose: string }

export interface Layer {
  slug: LayerSlug;
  number: string;
  osi: string;
  name: string;
  color: string;
  status: string;
  subtitle: string;
  pdu: string;
  address: string;
  adds: string;
  scope: string;
  purpose: string;
  why: string;
  parts: { name: string; description: string }[];
  gotchas: { title: string; description: string }[];
  files: { path: string; description: string }[];
  pduNote: string;
  fields: HeaderField[];
  send: string;
  receive: string;
}

export const layers: Layer[] = [
  {
    slug: 'application',
    number: 'L5–7',
    osi: 'OSI layers 5–7',
    name: 'Application',
    color: '#a99bff',
    status: 'Planned',
    subtitle: 'Give the bytes meaning: messages, formats, and conversations.',
    pdu: 'Data / message',
    address: 'Protocol-specific names',
    adds: 'Application framing & encoding',
    scope: 'Folder reserved',
    purpose: 'The application decides what a message means. HTTP, DNS, and your own protocols define how to encode requests and interpret responses. The grouped OSI layers also cover session management and representation, such as encryption and serialization.',
    why: 'A transport can deliver bytes without knowing whether they represent a web page, a file, or a command. Keeping meaning here lets the same lower layers carry many applications.',
    parts: [
      {
        name: 'Message framing',
        description: 'Length prefixes, delimiters, or protocol grammar tell a receiver where a message ends.'
      },
      {
        name: 'Presentation & sessions',
        description: 'Encoding, compression, authentication, and TLS belong above transport in this teaching model.'
      }
    ],
    gotchas: [
      {
        title: 'A write is not a message boundary',
        description: 'TCP is a byte stream. One write can arrive across several reads, and multiple writes can arrive in one read. The application must frame its messages.'
      },
      {
        title: 'A successful send is not an application acknowledgment',
        description: 'Even a TCP acknowledgment only confirms receipt by the peer’s TCP stack, not that the application processed or saved the data.'
      },
      {
        title: 'Planned means planned',
        description: 'TCP.Core has an application-layer README, not an HTTP, DNS, TLS, or session implementation.'
      }
    ],
    files: [
      {
        path: 'L5_7.Application/README.md',
        description: 'Reserved home for protocols built on L4.Transport.'
      }
    ],
    pduNote: 'There is no fixed header size for this group of layers. The lab’s application bytes are already encoded; any TLS or application overhead would be part of those bytes.',
    fields: [
      {
        name: 'Message / data',
        bits: 'Variable',
        purpose: 'Protocol-specific structure; no universal application header.'
      },
      {
        name: 'Encoding / framing',
        bits: 'Variable',
        purpose: 'Decided by the application protocol, not by IPv4.'
      }
    ],
    send: 'Start with application bytes. A future application protocol decides their meaning and message boundaries.',
    receive: 'The application decodes the reassembled byte stream and recognizes complete messages.'
  },
  {
    slug: 'transport',
    number: 'L4',
    osi: 'OSI layer 4',
    name: 'Transport',
    color: '#6cafff',
    status: 'TCP implemented',
    subtitle: 'Connect processes, not just machines. Choose streams or datagrams.',
    pdu: 'TCP segment / UDP datagram',
    address: 'Ports (16 bits each)',
    adds: 'TCP 20–60 B / UDP 8 B',
    scope: 'TCP streams & recovery; UDP planned',
    purpose: 'TCP provides an ordered byte stream using sequence numbers, acknowledgments, retransmission, flow control, and congestion control. UDP provides independent datagrams with much less machinery. Ports identify the endpoints within each host.',
    why: 'IP delivery can lose, duplicate, or reorder packets. Transport provides the communication behavior an application needs while keeping Ethernet addresses and ARP out of its API.',
    parts: [
      {
        name: 'TCP: reliability and pacing',
        description: 'Sequence numbers track bytes. The receive window limits outstanding data; congestion control limits pressure on the network.'
      },
      {
        name: 'UDP: planned',
        description: 'A fixed 8-byte header identifies ports, length, and checksum. Delivery, ordering, and retries remain the application’s responsibility.'
      },
      {
        name: 'MSS: TCP data budget',
        description: 'The SYN option advertises a receive limit. Each direction can have a different MSS.'
      }
    ],
    gotchas: [
      {
        title: 'MSS is not MTU',
        description: 'MSS counts TCP data under the fixed-header assumption. Actual IP/TCP options consume extra space, so the sender reduces its data. It is advertised in SYN segments, not renegotiated for every packet.'
      },
      {
        title: 'TCP segmentation is not IP fragmentation',
        description: 'TCP creates separate segments with their own TCP headers. IPv4 fragmentation splits one IP payload; its fragments are reassembled before transport processes it.'
      },
      {
        title: 'Checksums cover different things',
        description: 'TCP checksums include the TCP header, data, and an IP pseudo-header. The IPv4 checksum only covers the IPv4 header. UDP over IPv4 may omit its checksum; TCP cannot.'
      },
      {
        title: 'A baseline IPv4 TCP endpoint',
        description: 'TcpHost handles active/passive open, full-duplex streams, Reno recovery, persist probes, FIN/RST and TIME-WAIT. All calls share the stack thread. UDP, IPv6, window scaling, SACK and timestamps are not implemented.'
      }
    ],
    files: [
      {
        path: 'L4.Transport/Tcp/Segments/TcpSegment.cs',
        description: 'TCP header, option validation, MSS and IPv4 pseudo-header checksum.'
      },
      {
        path: 'L4.Transport/Tcp/TcpHost.cs',
        description: 'Listeners, connection four-tuples, sequence initialization, resets and ICMP feedback.'
      },
      {
        path: 'L4.Transport/Tcp/Connections/TcpConnection.cs',
        description: 'State machine, bounded stream buffers, sequencing, windows, retransmission and graceful close.'
      },
      {
        path: 'L3.Network/IPv4Host.cs',
        description: 'Owns Tcp, registers protocol 6, and drives transport timers.'
      },
      {
        path: 'L4.Transport/README.md',
        description: 'API examples, threading contract, capabilities and protocol limits.'
      }
    ],
    pduNote: 'TCP has a 20-byte fixed header, with up to 40 bytes of word-aligned options. TcpSegment implements the codec and MSS option. Optional performance extensions such as SACK, timestamps and window scaling are not negotiated.',
    fields: [
      {
        name: 'Source / destination ports',
        bits: '16 + 16',
        purpose: 'Which processes are talking.'
      },
      {
        name: 'Sequence number',
        bits: '32',
        purpose: 'Position in the byte stream.'
      },
      {
        name: 'Acknowledgment number',
        bits: '32',
        purpose: 'Next expected sequence number.'
      },
      {
        name: 'Data offset / reserved / flags',
        bits: '4 + 4 + 8',
        purpose: 'Header length in 32-bit words; CWR, ECE, URG, ACK, PSH, RST, SYN, FIN.'
      },
      {
        name: 'Window',
        bits: '16',
        purpose: 'Receive flow control; scaling may be negotiated.'
      },
      {
        name: 'Checksum / urgent pointer',
        bits: '16 + 16',
        purpose: 'Integrity including pseudo-header; urgent-data marker.'
      },
      {
        name: 'Options & padding',
        bits: '0–320',
        purpose: 'MSS, window scale, SACK, timestamps; padded to 4 bytes.'
      },
      {
        name: 'TCP data',
        bits: 'Variable',
        purpose: 'Application stream bytes.'
      }
    ],
    send: 'TCP divides the stream into MSS-sized segments, adds ports and sequence numbers, and retains unacknowledged bytes for retransmission.',
    receive: 'TCP validates its checksum, buffers out-of-order bytes, acknowledges progress, and exposes an ordered stream. UDP remains planned.'
  },
  {
    slug: 'network',
    number: 'L3',
    osi: 'OSI layer 3',
    name: 'Network',
    color: '#7ee7c5',
    status: 'Implemented subset',
    subtitle: 'Get an IP datagram to its destination, one next hop at a time.',
    pdu: 'IPv4 packet / datagram',
    address: 'IPv4 addresses (32 bits each)',
    adds: 'IPv4 20–60 B',
    scope: 'IPv4, ICMP, routes & fragments',
    purpose: 'IPv4 carries an upper-layer payload between IP addresses. A route selects the next hop and an MTU. The header describes packet length, lifetime, protocol, and fragmentation; ICMP carries diagnostics and errors alongside IPv4.',
    why: 'An Ethernet frame only reaches a local link. IP provides an address and delivery model across networks. An IP address identifies the destination; a next-hop MAC gets the frame through the current link.',
    parts: [
      {
        name: 'IPv4Packet & IPv4Host',
        description: 'Parse and validate headers, deliver local traffic, process options, dispatch protocols, and send through a link abstraction.'
      },
      {
        name: 'Routes, fragments & reassembly',
        description: 'Choose a next hop; split oversized datagrams when allowed; bound incomplete assemblies and reject overlaps.'
      },
      {
        name: 'ICMP & checksums',
        description: 'Echo request/reply, selected errors and redirects. InternetChecksum provides the 16-bit one’s-complement checksum.'
      }
    ],
    gotchas: [
      {
        title: 'Header length is not always 20 bytes',
        description: 'IHL counts 32-bit words. Honor total length rather than consuming Ethernet padding as IP data. IPv4Packet validates both lengths and the header checksum.'
      },
      {
        title: 'Fragment offsets count units of eight bytes',
        description: 'All non-final fragment payload lengths must be multiples of eight. Reassemble before interpreting transport. Missing fragments prevent delivery of the original datagram.'
      },
      {
        title: 'This host is not an IP router',
        description: 'IPv4Host delivers local/broadcast destinations; its route table serves locally originated sends. Do not infer router forwarding from the presence of routes.'
      },
      {
        title: 'Off-subnet sends are conservative',
        description: 'The current SendIPv4 and FragmentForTransmit paths cap off-subnet MTU at 576 bytes. This app’s generic size lab does not apply that implementation-specific cap.'
      },
      {
        title: 'DF and path MTU need careful handling',
        description: 'SendIPv4 returns false when its MTU check fails with DF set. Internet routers may report ICMP fragmentation-needed. TCP validates the quoted connection/sequence, reduces its packet budget, and retransmits smaller segments. Automatic upward path-MTU probing is not implemented.'
      }
    ],
    files: [
      {
        path: 'L3.Network/IPv4Host.cs',
        description: 'Local receive/send, ICMP, option processing, protocol registration; default MTU 1500.'
      },
      {
        path: 'L3.Network/IIPv4Link.cs',
        description: 'IsReady, SendToNeighbor and SendBroadcast separate IP from its link.'
      },
      {
        path: 'L3.Network/IPv4/IPv4Packet.cs',
        description: '20–60-byte header codec; total length, network byte order, and checksum validation.'
      },
      {
        path: 'L3.Network/IPv4/Routing/IPv4RouteTable.cs',
        description: 'Routes, next-hop lookup and expiring redirect entries.'
      },
      {
        path: 'L3.Network/IPv4/Fragmentation/IPv4Fragmenter.cs',
        description: 'MTU/DF checks and 8-byte fragment boundaries.'
      },
      {
        path: 'L3.Network/IPv4/Fragmentation/IPv4Reassembler.cs',
        description: 'Bounded pending assemblies, timeouts and overlap rejection.'
      },
      {
        path: 'L3.Network/IPv4/Options/IPv4Options.cs',
        description: 'Option parsing/processing and copied-option handling for fragments.'
      },
      {
        path: 'L3.Network/IPv4/Routing/IPv4Subnet.cs',
        description: 'Subnet membership, source validation and connected next-hop logic.'
      },
      {
        path: 'L3.Network/Icmp/IcmpPacket.cs',
        description: 'ICMP codec and checksum; echo and error types live in the Icmp folder.'
      },
      {
        path: 'Checksums/InternetChecksum.cs',
        description: 'Shared Internet checksum calculation and validation.'
      }
    ],
    pduNote: 'The IPv4 PDU includes its header and its complete payload. Protocol 6 selects TCP, 17 UDP, and 1 ICMP. ICMP is an L3 control protocol, not a transport layer.',
    fields: [
      {
        name: 'Version / IHL',
        bits: '4 + 4',
        purpose: 'IPv4 = 4; IHL × 4 gives header bytes.'
      },
      {
        name: 'DSCP / ECN',
        bits: '6 + 2',
        purpose: 'Traffic classification and congestion signals.'
      },
      {
        name: 'Total length',
        bits: '16',
        purpose: 'IP header + payload; maximum 65,535 B.'
      },
      {
        name: 'Identification',
        bits: '16',
        purpose: 'Associates fragments of one datagram.'
      },
      {
        name: 'Flags / fragment offset',
        bits: '3 + 13',
        purpose: 'Reserved, DF, MF; offset in 8-byte units.'
      },
      {
        name: 'TTL / protocol',
        bits: '8 + 8',
        purpose: 'Lifetime / next protocol (TCP 6, UDP 17, ICMP 1).'
      },
      {
        name: 'Header checksum',
        bits: '16',
        purpose: 'Protects the IP header, not its payload.'
      },
      {
        name: 'Source / destination IP',
        bits: '32 + 32',
        purpose: 'Sender and destination IPv4 addresses.'
      },
      {
        name: 'Options & padding',
        bits: '0–320',
        purpose: 'Optional fields, padded to 4-byte words.'
      },
      {
        name: 'IP payload',
        bits: 'Variable',
        purpose: 'TCP, UDP, ICMP, or another IP protocol.'
      }
    ],
    send: 'IPv4 adds source/destination IPs and selects a route and MTU. Oversized datagrams may fragment unless DF forbids it.',
    receive: 'Validate IPv4, process/reassemble fragments, and dispatch a complete payload by protocol number. ICMP is handled here.'
  },
  {
    slug: 'link',
    number: 'L2',
    osi: 'OSI layer 2',
    name: 'Link',
    color: '#f1be73',
    status: 'Implemented subset',
    subtitle: 'Deliver a frame across this link using hardware addresses.',
    pdu: 'Ethernet frame',
    address: 'MAC addresses (48 bits each)',
    adds: '14 B header + 4 B FCS; tag +4 B',
    scope: 'Ethernet, ARP, VLAN bridge & STP',
    purpose: 'Ethernet wraps an IP packet in a frame for the next hop. ARP resolves an on-link IPv4 address to a MAC address. A learning bridge forwards frames by VLAN and learned MAC; spanning tree can block redundant paths to prevent loops.',
    why: 'Routing chooses where to go next; the link layer supplies the local delivery mechanism. A remote IP destination usually requires your gateway’s MAC, not the remote host’s MAC.',
    parts: [
      {
        name: 'Ethernet + ARP',
        description: 'Ethernet II and LLC/SNAP codecs, optional single VLAN tag, ARP requests/replies, expiring cache, active retries, queued packets, and address-conflict probing.'
      },
      {
        name: 'Bridge + spanning tree',
        description: 'Separate VLAN-aware LearningBridge with MAC learning/aging and optional classic common spanning tree.'
      },
      {
        name: 'EthernetStack',
        description: 'Connects an IPacketInterface to IPv4Host; filters frames, dispatches EtherTypes, resolves neighbors, and drives timers.'
      }
    ],
    gotchas: [
      {
        title: 'A 1500-byte MTU is not a 1500-byte frame',
        description: 'An untagged 1500-byte IP packet occupies 1514 bytes without FCS, or 1518 with FCS. Preamble and inter-frame gap are separate from that frame count.'
      },
      {
        title: 'FCS is outside the codec',
        description: 'EthernetFrame excludes preamble and FCS. The physical interface/NIC handles them. Small untagged frames are padded to at least 60 bytes before the 4-byte FCS.'
      },
      {
        title: 'ARP is not inside an IP packet',
        description: 'EtherType 0x0806 directly selects ARP; 0x0800 selects IPv4. The Ethernet/IPv4 ARP body is 28 bytes, then Ethernet padding may follow.'
      },
      {
        title: 'Host and bridge have different VLAN scope',
        description: 'The codec handles one tag and the separate bridge is VLAN-aware. EthernetStack accepts untagged/priority-tagged traffic and rejects nonzero VLAN IDs.'
      },
      {
        title: 'Switches do not negotiate MSS',
        description: 'A bridge applies its frame-size and forwarding rules. It does not fragment IPv4, rewrite IP routes, or run TCP flow control.'
      }
    ],
    files: [
      {
        path: 'L2.Link/Ethernet/EthernetFrame.cs',
        description: 'Ethernet II / LLC-SNAP parse and serialize, optional VLAN and minimum padding.'
      },
      {
        path: 'L2.Link/Ethernet/MacAddress.cs',
        description: 'Six-byte address representation, parsing and multicast classification.'
      },
      {
        path: 'L2.Link/Arp/ArpPacket.cs',
        description: '28-byte Ethernet/IPv4 ARP request and reply format.'
      },
      {
        path: 'L2.Link/Arp/ArpCache.cs',
        description: 'Bounded, expiring neighbor mappings.'
      },
      {
        path: 'L2.Link/Arp/ArpResolver.cs',
        description: 'Active resolution, pending traffic and retries.'
      },
      {
        path: 'L2.Link/Arp/AddressClaim.cs',
        description: 'Startup address-conflict probes and announcements.'
      },
      {
        path: 'L2.Link/Arp/ArpResponder.cs',
        description: 'Replies for the configured local address.'
      },
      {
        path: 'L2.Link/Bridge/LearningBridge.cs',
        description: 'VLAN-aware MAC learning, aging and frame forwarding.'
      },
      {
        path: 'L2.Link/Bridge/SpanningTree.cs',
        description: 'Classic common spanning tree; BPDUs, timers and port states.'
      },
      {
        path: 'Stack/EthernetStack.cs',
        description: 'L2/L3 composition, frame filters, ARP and timer loop.'
      }
    ],
    pduNote: 'Ethernet II’s untagged header is 14 bytes. Optional 802.1Q tagging adds 4 bytes. The 4-byte FCS is a trailer handled below TCP.Core’s frame codec.',
    fields: [
      {
        name: 'Destination MAC',
        bits: '48',
        purpose: 'Next-hop hardware address.'
      },
      {
        name: 'Source MAC',
        bits: '48',
        purpose: 'This interface’s hardware address.'
      },
      {
        name: 'Optional 802.1Q tag',
        bits: '32',
        purpose: 'TPID 16; priority 3, DEI 1, VLAN ID 12.'
      },
      {
        name: 'EtherType',
        bits: '16',
        purpose: 'IPv4 0x0800; ARP 0x0806.'
      },
      {
        name: 'Payload + padding',
        bits: 'Variable',
        purpose: 'IP packet or ARP, padded as needed.'
      },
      {
        name: 'FCS (outside codec)',
        bits: '32',
        purpose: 'CRC error detection, normally handled by NIC/driver.'
      }
    ],
    send: 'Resolve the next-hop MAC with ARP, then wrap the IPv4 packet in Ethernet addresses and an EtherType.',
    receive: 'Filter the destination MAC and inspect EtherType: ARP stays at the link; IPv4 is passed to IPv4Host.'
  },
  {
    slug: 'physical',
    number: 'L1',
    osi: 'OSI layer 1',
    name: 'Physical',
    color: '#99acbe',
    status: 'Interface abstraction',
    subtitle: 'Move signals on the medium. Expose frames to the software.',
    pdu: 'Bits / symbols on a medium',
    address: 'Physical port / medium',
    adds: 'Signaling, synchronization & encoding',
    scope: 'IPacketInterface; pcap adapter outside core',
    purpose: 'Real physical networking encodes bits as electrical, optical, or radio signals. TCP.Core does not model those signals. Its IPacketInterface is a frame-level boundary to the operating system and hardware.',
    why: 'The core can process Ethernet frames without depending on a particular capture library or network adapter. A real adapter or an in-memory test double can implement the same contract.',
    parts: [
      {
        name: 'IPacketInterface',
        description: 'Receive(byte[]) returns immediately when no frame is available. Send(byte[]) transmits one frame; Dispose releases the interface.'
      },
      {
        name: 'PcapPacketInterface in TCP.Networking.Pcap',
        description: 'A separate adapter project connects the core to packet capture/injection. Physical encoding and NIC framing remain outside TCP.Core.'
      }
    ],
    gotchas: [
      {
        title: 'The folder name is a teaching boundary',
        description: 'The L1 API actually exchanges whole Ethernet frames, not raw bits. A pcap adapter is not a simulation of cables, clock recovery, or radio modulation.'
      },
      {
        title: 'Bytes on the wire differ from captured bytes',
        description: 'A capture often omits Ethernet preamble and FCS; offloading can also affect what a capture shows. Do not assume a software buffer is the entire physical transmission.'
      },
      {
        title: 'Blocking receive stalls timers',
        description: 'IPacketInterface requires an immediate no-frame return. EthernetStack drives ARP and IPv4 timers in the same receive loop.'
      }
    ],
    files: [
      {
        path: 'L1.Physical/IPacketInterface.cs',
        description: 'InterfaceName, nonblocking Receive, Send and IDisposable.'
      },
      {
        path: '../TCP.Networking.Pcap/PcapPacketInterface.cs',
        description: 'The platform adapter is outside TCP.Core, in TCP.Networking.Pcap.'
      },
      {
        path: 'Stack/EthernetStack.cs',
        description: 'The receive loop drives protocol processing and periodic Tick calls.'
      }
    ],
    pduNote: 'A bit count is not a universal symbol count; encoding depends on the Ethernet PHY. This illustration shows logical Ethernet transmission components, not a PHY implementation.',
    fields: [
      {
        name: 'Preamble + SFD',
        bits: '56 + 8',
        purpose: 'Synchronization and start delimiter before the MAC frame.'
      },
      {
        name: 'MAC frame including FCS',
        bits: 'Variable',
        purpose: 'Bytes produced above plus hardware-managed framing.'
      },
      {
        name: 'Inter-frame gap',
        bits: '96 bit-times',
        purpose: 'Idle time equivalent to 12 octets; not 12 bytes of frame data.'
      }
    ],
    send: 'The adapter hands a frame to the NIC. Hardware supplies framing and transmits encoded symbols on the medium.',
    receive: 'Hardware receives signals and exposes a frame through the adapter; TCP.Core begins with those frame bytes.'
  }
];

/** Alternative header layouts shown beside a layer's main protocol. */
export interface HeaderVariant { protocol: string; note?: string; fields?: HeaderField[] }

export const headerVariants: Partial<Record<LayerSlug, HeaderVariant[]>> = {
  transport: [
    { protocol: 'TCP' },
    { protocol: 'UDP', note: 'UDP has a fixed 8-byte header. It preserves datagram boundaries and has no MSS option. TCP.Core does not implement UDP yet.', fields: [
  {
    name: 'Source / destination ports',
    bits: '16 + 16',
    purpose: 'Process endpoints.'
  },
  {
    name: 'Length',
    bits: '16',
    purpose: '8-byte UDP header plus UDP data.'
  },
  {
    name: 'Checksum',
    bits: '16',
    purpose: 'UDP plus IP pseudo-header; optional in IPv4.'
  },
  {
    name: 'UDP data',
    bits: 'Variable',
    purpose: 'One application datagram.'
  }
] }
  ],
  network: [
    { protocol: 'IPv4' },
    { protocol: 'ICMP echo', note: 'ICMP echo has an 8-byte header and variable data, carried directly inside IPv4 (protocol 1). There are no transport ports. Other ICMP message layouts differ.', fields: [
  {
    name: 'Type / code',
    bits: '8 + 8',
    purpose: 'Echo request 8/0, echo reply 0/0.'
  },
  {
    name: 'Checksum',
    bits: '16',
    purpose: 'Covers the entire ICMP message.'
  },
  {
    name: 'Identifier / sequence',
    bits: '16 + 16',
    purpose: 'Echo matching; other ICMP types use this space differently.'
  },
  {
    name: 'Echo data',
    bits: 'Variable',
    purpose: 'Reflected by an echo reply.'
  }
] }
  ],
  link: [
    { protocol: 'Ethernet' },
    { protocol: 'ARP', note: 'For Ethernet and IPv4, ARP is a 28-byte message directly inside an Ethernet frame (EtherType 0x0806). It has no IP or transport header.', fields: [
  {
    name: 'Hardware / protocol type',
    bits: '16 + 16',
    purpose: 'Ethernet = 1; IPv4 = 0x0800.'
  },
  {
    name: 'Hardware / protocol length',
    bits: '8 + 8',
    purpose: 'MAC addresses are 6 B; IPv4 addresses are 4 B.'
  },
  {
    name: 'Operation',
    bits: '16',
    purpose: 'Request = 1; reply = 2.'
  },
  {
    name: 'Sender hardware / protocol address',
    bits: '48 + 32',
    purpose: 'Sender MAC and IPv4 address.'
  },
  {
    name: 'Target hardware / protocol address',
    bits: '48 + 32',
    purpose: 'Target MAC and IPv4 address; MAC is unknown in an initial request.'
  }
] }
  ]
};

export const findLayer = (slug: string | undefined): Layer | undefined => layers.find(layer => layer.slug === slug);
