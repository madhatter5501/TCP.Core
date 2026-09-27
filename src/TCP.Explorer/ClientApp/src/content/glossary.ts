import type { LayerSlug } from './layers';

/**
 * Networking vocabulary used across the Explorer. Definitions describe the general concept first,
 * then (in `inCode`) how TCP.Core handles it, so keep that part in step with the implementation.
 *
 * `matches` lists the exact spellings that are linked automatically in the app's prose (case-sensitive,
 * whole words). Only list spellings that are unambiguous wherever they appear.
 */

export interface GlossaryEntry {
  id: string;
  term: string;
  expansion?: string;
  /** The layers the term belongs to, lowest first. Empty for ideas that apply at every layer. */
  layers: LayerSlug[];
  definition: string;
  inCode?: string;
  related?: string[];
  /** An Explorer page that shows the idea in action. */
  see?: { to: string; label: string };
  matches?: string[];
}

export const glossary: GlossaryEntry[] = [
  {
    id: 'ack', term: 'ACK', expansion: 'Acknowledgment', layers: ['transport'], matches: ['ACK', 'ACKs'],
    definition: 'A TCP flag and 32-bit field. The acknowledgment number is the next byte the receiver expects, so it confirms every byte before it (a cumulative acknowledgment). Repeated identical ACKs (duplicate ACKs) hint that a segment went missing.',
    inCode: 'TCP.Core acknowledges immediately; it does not delay ACKs.',
    related: ['sequence-number', 'retransmission'], see: { to: '/transmit?scenario=tcp-loss', label: 'Watch duplicate ACKs after a loss' }
  },
  {
    id: 'arp', term: 'ARP', expansion: 'Address Resolution Protocol', layers: ['link'], matches: ['ARP'],
    definition: 'Finds the MAC address that owns an IPv4 address on the local link. A host broadcasts “who has 192.0.2.20?” and the owner replies with its MAC. Results are cached for a while. ARP rides directly in an Ethernet frame (EtherType 0x0806), not inside IP.',
    inCode: 'ArpResolver queues packets while resolving, retries, and gives up with NeighborResolutionFailed. ArpCache entries expire.',
    related: ['mac-address', 'broadcast', 'next-hop'], see: { to: '/transmit?scenario=ping', label: 'See ARP before a ping' }
  },
  {
    id: 'broadcast', term: 'Broadcast', layers: ['link'],
    definition: 'A frame addressed to FF:FF:FF:FF:FF:FF, which every host on the local link receives. ARP requests are broadcast because the sender does not yet know whose MAC it needs.',
    related: ['arp', 'mac-address']
  },
  {
    id: 'checksum', term: 'Checksum', expansion: 'Internet checksum', layers: ['network', 'transport'],
    definition: 'A 16-bit one’s-complement sum a receiver recomputes to detect damage. The IPv4 checksum covers only the IPv4 header; TCP, UDP and ICMP checksums cover their own header and data (TCP and UDP also include a pseudo-header). A mismatch means the packet is silently discarded.',
    inCode: 'Checksums/InternetChecksum.cs, shared by IPv4, ICMP and TCP.',
    related: ['pseudo-header', 'fcs'], see: { to: '/transmit?scenario=checksum', label: 'Corrupt an IPv4 checksum' }
  },
  {
    id: 'congestion-control', term: 'Congestion control', layers: ['transport'],
    definition: 'Sender-side pacing that protects the network, separate from the receiver’s window. The congestion window starts small (slow start), grows while data is acknowledged, and shrinks when loss suggests the path is overloaded.',
    inCode: 'Slow start, congestion avoidance, fast retransmit and NewReno recovery (RFC 5681, RFC 6582).',
    related: ['window', 'retransmission']
  },
  {
    id: 'crc', term: 'CRC', expansion: 'Cyclic redundancy check', layers: ['link'], matches: ['CRC'],
    definition: 'An error-detecting code computed by polynomial division over the data. Much stronger than a simple sum at catching burst errors on the wire. Ethernet’s FCS is a 32-bit CRC.',
    related: ['fcs', 'checksum']
  },
  {
    id: 'datagram', term: 'Datagram', layers: ['network', 'transport'],
    definition: 'A self-contained unit of data carrying its own addresses, delivered independently and on a best-effort basis: it may be lost, duplicated or reordered. IPv4 and UDP both call their PDU a datagram.',
    related: ['pdu', 'segment', 'fragment'], see: { to: '/concepts/datagram', label: 'Read the datagram article' }
  },
  {
    id: 'df', term: 'DF', expansion: 'Don’t Fragment', layers: ['network'], matches: ['DF'],
    definition: 'An IPv4 header flag. When set, a packet too large for the next link must be dropped rather than fragmented; a router normally reports ICMP “fragmentation needed” (type 3, code 4) so the sender can shrink its packets.',
    inCode: 'TCP sends DF-marked packets. SendIPv4 returns false instead of fragmenting when a DF packet exceeds the MTU.',
    related: ['fragment', 'path-mtu', 'mf'], see: { to: '/transmit?scenario=df', label: 'Send an oversized DF packet' }
  },
  {
    id: 'encapsulation', term: 'Encapsulation', layers: [],
    definition: 'Wrapping one layer’s data inside the next layer’s header (and sometimes trailer) on the way down; decapsulation unwraps it on the way up. Application data becomes a TCP segment, inside an IP datagram, inside an Ethernet frame.',
    related: ['pdu'], see: { to: '/layers/application', label: 'Walk the layers' }
  },
  {
    id: 'ethernet-frame', term: 'Ethernet frame', layers: ['link'],
    definition: 'The link-layer PDU: destination MAC, source MAC, optional VLAN tag, EtherType, payload (padded to a minimum), then the FCS. An untagged frame carrying a 1500-byte IP packet is 1518 bytes including the FCS.',
    inCode: 'L2.Link/Ethernet/EthernetFrame.cs. Serialized frames exclude preamble and FCS.',
    related: ['mac-address', 'ethertype', 'fcs', 'padding'], see: { to: '/layers/link/headers', label: 'Ethernet header fields' }
  },
  {
    id: 'ethertype', term: 'EtherType', layers: ['link'], matches: ['EtherType'],
    definition: 'The 16-bit Ethernet field that says what the payload is: 0x0800 for IPv4, 0x0806 for ARP. The value 0x8100 in that position instead marks an 802.1Q VLAN tag.',
    related: ['ethernet-frame', 'vlan']
  },
  {
    id: 'fcs', term: 'FCS', expansion: 'Frame Check Sequence', layers: ['link'], matches: ['FCS'],
    definition: 'The 4-byte trailer at the end of every Ethernet frame: a CRC-32 the sending network card computes over the whole frame. The receiving card recomputes it and silently drops any frame that does not match. Hardware adds and strips it, so software and most packet captures never see it.',
    inCode: 'EthernetFrame excludes the FCS, so frame sizes in this app say “plus 4-byte FCS” where it matters.',
    related: ['crc', 'ethernet-frame', 'checksum'], see: { to: '/sizes', label: 'See it in the byte breakdown' }
  },
  {
    id: 'fin', term: 'FIN', expansion: 'Finish', layers: ['transport'], matches: ['FIN'],
    definition: 'A TCP flag meaning “I have no more data to send.” Each direction closes separately, so a connection can be half-closed: one side has finished writing but can still read.',
    related: ['time-wait', 'rst'], see: { to: '/transmit?scenario=tcp', label: 'Watch the FIN exchange' }
  },
  {
    id: 'four-tuple', term: 'Four-tuple', layers: ['transport'],
    definition: 'Source IP, source port, destination IP and destination port. Together they identify one TCP connection, which is how one server port can serve many clients at once.',
    related: ['port']
  },
  {
    id: 'fragment', term: 'Fragment', layers: ['network'],
    definition: 'A piece of an IPv4 datagram that was too large for a link’s MTU. Each fragment is its own IP packet with a copied header, the same Identification, a fragment offset and the MF flag. The receiver must collect every piece; lose one and the whole datagram is lost.',
    inCode: 'L3.Network/IPv4/Fragmentation: IPv4Fragmenter splits, IPv4Reassembler rebuilds with bounded, time-limited assemblies.',
    related: ['fragment-offset', 'mf', 'df', 'identification', 'reassembly'], see: { to: '/transmit?scenario=fragment', label: 'Fragment and reassemble' }
  },
  {
    id: 'fragment-offset', term: 'Fragment offset', layers: ['network'], matches: ['fragment offset', 'fragment offsets'],
    definition: 'Where a fragment’s data belongs in the original datagram, counted in 8-byte units. That is why every fragment except the last carries a multiple of 8 data bytes.',
    related: ['fragment', 'mf']
  },
  {
    id: 'handshake', term: 'Three-way handshake', layers: ['transport'], matches: ['three-way handshake'],
    definition: 'How TCP opens a connection: SYN, then SYN-ACK, then ACK. Each side picks an initial sequence number and advertises options such as MSS.',
    related: ['syn', 'ack', 'mss'], see: { to: '/transmit?scenario=tcp', label: 'See a handshake' }
  },
  {
    id: 'icmp', term: 'ICMP', expansion: 'Internet Control Message Protocol', layers: ['network'], matches: ['ICMP'],
    definition: 'IP’s companion for diagnostics and errors: echo request/reply (ping), destination unreachable, fragmentation needed, time exceeded. It rides directly inside IPv4 (protocol 1) and has no ports.',
    inCode: 'L3.Network/Icmp. Errors are rate-limited and validated against recently sent packets.',
    related: ['ipv4', 'ttl'], see: { to: '/layers/network/headers', label: 'ICMP echo fields' }
  },
  {
    id: 'identification', term: 'Identification', layers: ['network'],
    definition: 'A 16-bit IPv4 header field. All fragments of one datagram share it, so the receiver knows which pieces belong together.',
    inCode: 'IPv4IdentificationAllocator.',
    related: ['fragment']
  },
  {
    id: 'ihl', term: 'IHL', expansion: 'Internet Header Length', layers: ['network'], matches: ['IHL'],
    definition: 'The IPv4 header length in 32-bit words: 5 means 20 bytes (no options), 15 means the 60-byte maximum.',
    related: ['ipv4']
  },
  {
    id: 'ipv4', term: 'IPv4', expansion: 'Internet Protocol version 4', layers: ['network'],
    definition: 'The network layer protocol that carries datagrams between 32-bit addresses across networks, one next hop at a time. Best effort: no delivery, ordering or duplicate guarantees.',
    related: ['datagram', 'ttl', 'next-hop'], see: { to: '/layers/network', label: 'The network layer' }
  },
  {
    id: 'mac-address', term: 'MAC address', expansion: 'Media Access Control address', layers: ['link'], matches: ['MAC', 'MACs'],
    definition: 'A 48-bit hardware address, written like 02:00:00:00:00:0A. It only has meaning on the local link: to reach a remote host, a frame is addressed to the gateway’s MAC.',
    related: ['arp', 'next-hop', 'broadcast']
  },
  {
    id: 'message-framing', term: 'Message framing', layers: ['application'], matches: ['message boundary', 'message boundaries'],
    definition: 'How an application marks where one message ends and the next begins in a TCP byte stream: a length prefix, a delimiter such as a newline, or the protocol’s own grammar (HTTP headers, for example). TCP does not preserve write boundaries, so every application protocol over TCP needs one.',
    related: ['segment', 'datagram'], see: { to: '/layers/application/gotchas', label: 'Application-layer gotchas' }
  },
  {
    id: 'mf', term: 'MF', expansion: 'More Fragments', layers: ['network'], matches: ['MF'],
    definition: 'An IPv4 flag set on every fragment except the last. Together with the fragment offset it tells the receiver when it has the end of the datagram.',
    related: ['fragment', 'fragment-offset', 'df']
  },
  {
    id: 'msl', term: 'MSL', expansion: 'Maximum Segment Lifetime', layers: ['transport'], matches: ['MSL'],
    definition: 'An assumed upper bound on how long a stray packet can survive in the network. TCP’s TIME-WAIT lasts twice this, so old duplicates die before the same connection can be reused.',
    inCode: 'Two minutes, so TIME-WAIT lasts four.',
    related: ['time-wait']
  },
  {
    id: 'mss', term: 'MSS', expansion: 'Maximum Segment Size', layers: ['transport'], matches: ['MSS'],
    definition: 'The most TCP data (excluding headers) a host wants in one segment, advertised in the SYN. It is normally the MTU minus 40 bytes of fixed IPv4 and TCP headers: 1460 on Ethernet. Header options reduce the data actually sent.',
    inCode: 'A peer that sends no MSS option is assumed to accept 536 bytes.',
    related: ['mtu', 'segment', 'syn'], see: { to: '/sizes', label: 'Experiment with MSS' }
  },
  {
    id: 'mtu', term: 'MTU', expansion: 'Maximum Transmission Unit', layers: ['link', 'network'], matches: ['MTU', 'MTUs'],
    definition: 'The largest IP packet, including its IP header, a link can carry in one frame: 1500 bytes for standard Ethernet. It excludes the Ethernet header and FCS.',
    inCode: 'IPv4Host defaults to 1500. Off-subnet sends are capped at 576 bytes.',
    related: ['path-mtu', 'mss', 'fragment'], see: { to: '/sizes', label: 'Experiment with MTU' }
  },
  {
    id: 'nagle', term: 'Nagle’s algorithm', layers: ['transport'],
    definition: 'Holds back small writes while earlier data is unacknowledged and sends them together, trading a little latency for fewer tiny packets.',
    inCode: 'On by default; set NoDelay on a connection to disable it.',
    related: ['segment']
  },
  {
    id: 'next-hop', term: 'Next hop', layers: ['network'], matches: ['next hop', 'next-hop'],
    definition: 'The directly reachable machine a packet is handed to next: the destination itself if it is on the local subnet, otherwise a gateway (router). The route table picks it; ARP finds its MAC.',
    inCode: 'L3.Network/IPv4/Routing: IPv4RouteTable and IPv4Subnet.',
    related: ['arp', 'mac-address']
  },
  {
    id: 'octet', term: 'Octet', layers: [],
    definition: 'Exactly 8 bits. RFCs say octet rather than byte because some historical machines had bytes of other sizes.'
  },
  {
    id: 'padding', term: 'Padding', layers: ['link'],
    definition: 'Filler bytes added so an Ethernet frame reaches its 60-byte minimum (64 with FCS). A receiver uses the IP total length to ignore them.',
    inCode: 'EthernetFrame.Serialize pads to 60 bytes.',
    related: ['ethernet-frame']
  },
  {
    id: 'path-mtu', term: 'Path MTU', layers: ['network'], matches: ['path MTU', 'Path MTU'],
    definition: 'The smallest MTU along the whole route to a destination. Path MTU discovery sends DF packets and shrinks them when routers report “fragmentation needed.” If those ICMP messages are blocked, large packets vanish: a black hole.',
    inCode: 'TCP lowers its packet budget on validated fragmentation-needed errors; it does not probe upward again.',
    related: ['mtu', 'df', 'icmp']
  },
  {
    id: 'pdu', term: 'PDU', expansion: 'Protocol Data Unit', layers: [], matches: ['PDU', 'PDUs'],
    definition: 'What one layer hands to the layer below, including its own header: frame (link), packet or datagram (network), segment or datagram (transport).',
    related: ['encapsulation', 'datagram', 'segment'], see: { to: '/concepts/pdus', label: 'PDU names by layer' }
  },
  {
    id: 'port', term: 'Port', layers: ['transport'],
    definition: 'A 16-bit number identifying an endpoint within a host, so many applications can share one IP address. Servers listen on well-known ports; clients usually get a temporary (ephemeral) one.',
    inCode: 'Ephemeral ports are chosen from 49152–65535.',
    related: ['four-tuple']
  },
  {
    id: 'preamble', term: 'Preamble & SFD', expansion: 'Start Frame Delimiter', layers: ['physical'], matches: ['SFD'],
    definition: 'Seven bytes of alternating bits followed by one start-of-frame byte, sent before every Ethernet frame so the receiver can synchronize. Pure physical-layer signaling, never seen by software.',
    related: ['ethernet-frame', 'fcs']
  },
  {
    id: 'pseudo-header', term: 'Pseudo-header', layers: ['transport'], matches: ['pseudo-header'],
    definition: 'Source and destination IP, protocol number and segment length, included in the TCP and UDP checksum but never transmitted in the TCP header. It catches segments delivered to the wrong address.',
    related: ['checksum']
  },
  {
    id: 'reassembly', term: 'Reassembly', layers: ['network'],
    definition: 'Rebuilding the original datagram from its fragments at the destination. Only then does the payload go to TCP, UDP or ICMP. Incomplete assemblies are discarded after a timeout.',
    related: ['fragment']
  },
  {
    id: 'retransmission', term: 'Retransmission', layers: ['transport'],
    definition: 'Sending unacknowledged data again. Triggered by a timeout (RTO) or earlier by three duplicate ACKs (fast retransmit).',
    related: ['rto', 'ack'], see: { to: '/transmit?scenario=tcp-loss', label: 'Drop a segment and watch recovery' }
  },
  {
    id: 'rst', term: 'RST', expansion: 'Reset', layers: ['transport'], matches: ['RST'],
    definition: 'A TCP flag that aborts a connection immediately. Sent, for example, in reply to a SYN for a port nobody listens on.',
    related: ['fin', 'syn'], see: { to: '/transmit?scenario=tcp-refused', label: 'Connect to a closed port' }
  },
  {
    id: 'rto', term: 'RTO', expansion: 'Retransmission timeout', layers: ['transport'], matches: ['RTO'],
    definition: 'How long TCP waits for an acknowledgment before resending, derived from measured round-trip times and doubled after each timeout (exponential backoff).',
    inCode: 'Bounded to 1–60 seconds (RFC 6298).',
    related: ['rtt', 'retransmission']
  },
  {
    id: 'rtt', term: 'RTT', expansion: 'Round-trip time', layers: ['transport'], matches: ['RTT'],
    definition: 'The time from sending a segment to receiving its acknowledgment. TCP keeps a smoothed average and its variation to set the RTO.',
    related: ['rto']
  },
  {
    id: 'segment', term: 'Segment', layers: ['transport'],
    definition: 'TCP’s PDU: a TCP header plus a slice of the byte stream. Segment boundaries are invisible to applications, which see only a stream of bytes.',
    related: ['mss', 'sequence-number', 'datagram'], see: { to: '/layers/transport', label: 'The transport layer' }
  },
  {
    id: 'sequence-number', term: 'Sequence number', layers: ['transport'],
    definition: 'The 32-bit position of a segment’s first data byte in the stream. Receivers use it to reorder, discard duplicates and acknowledge. It wraps around after 4 GiB.',
    related: ['ack', 'segment']
  },
  {
    id: 'syn', term: 'SYN', expansion: 'Synchronize', layers: ['transport'], matches: ['SYN'],
    definition: 'A TCP flag that opens a connection and carries the initial sequence number and options such as MSS.',
    related: ['handshake', 'mss']
  },
  {
    id: 'time-wait', term: 'TIME-WAIT', layers: ['transport'], matches: ['TIME-WAIT'],
    definition: 'The state the side that closes first stays in for 2 × MSL, so a lost final ACK can be resent and old duplicates cannot leak into a new connection.',
    related: ['msl', 'fin']
  },
  {
    id: 'ttl', term: 'TTL', expansion: 'Time to live', layers: ['network'], matches: ['TTL'],
    definition: 'An IPv4 hop counter. Each router decrements it and discards the packet at zero, reporting ICMP “time exceeded,” so routing loops cannot circulate packets forever.',
    inCode: 'Outgoing packets default to 64.',
    related: ['icmp']
  },
  {
    id: 'udp', term: 'UDP', expansion: 'User Datagram Protocol', layers: ['transport'], matches: ['UDP'],
    definition: 'A minimal transport: ports, a length and a checksum over IP’s datagram service. No connection, retransmission or ordering; message boundaries are preserved.',
    inCode: 'Not implemented yet.',
    related: ['datagram', 'port'], see: { to: '/concepts/datagram', label: 'Datagrams vs streams' }
  },
  {
    id: 'vlan', term: 'VLAN tag', expansion: 'IEEE 802.1Q', layers: ['link'], matches: ['VLAN', '802.1Q'],
    definition: 'A 4-byte field inserted after the source MAC that places a frame on a virtual LAN (12-bit VLAN ID) and gives it a priority. It grows the frame, not the IP packet.',
    inCode: 'The codec handles one tag. EthernetStack accepts only untagged or priority-tagged traffic; the separate LearningBridge is VLAN-aware.',
    related: ['ethertype', 'ethernet-frame']
  },
  {
    id: 'window', term: 'Receive window', layers: ['transport'], matches: ['receive window', 'zero window', 'zero-window'],
    definition: 'Flow control: how many more bytes the receiver can buffer, advertised in every segment. At zero the sender stops and sends periodic probes until space opens.',
    inCode: '16-bit windows (no window scaling); 65,535-byte default receive capacity.',
    related: ['congestion-control'], see: { to: '/transmit?scenario=tcp-window', label: 'Zero-window recovery' }
  }
];

export const glossaryById = new Map(glossary.map(entry => [entry.id, entry]));
