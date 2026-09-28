import type { LayerSlug } from '../../content/layers';
import type { ScenarioId } from './types';

export interface Scenario {
  id: ScenarioId;
  /** Option group, labeled with the layer the experiment exercises. */
  group: 'L4 · TCP' | 'L3 · IPv4 & ICMP';
  label: string;
  /** The layer whose behavior the experiment shows. */
  layer: LayerSlug;
  /** The fault the virtual link or host injects, if any. */
  fault?: string;
  /** What the experiment does and what to look for in the capture. */
  description: string;
  defaultPayload: number;
}

export const scenarios: Scenario[] = [
  { id: 'tcp', group: 'L4 · TCP', label: 'Stream & graceful close', layer: 'transport', defaultPayload: 4000,
    description: 'Host A opens a connection, streams the payload, and Host B’s demo application echoes it. Watch the three-way handshake, MSS-sized segments, ACKs, and the FIN exchange.' },
  { id: 'tcp-loss', group: 'L4 · TCP', label: 'Drop a data segment', layer: 'transport', fault: 'drop', defaultPayload: 4000,
    description: 'The virtual link drops the first TCP data segment. Look for duplicate ACKs and the retransmission that fills the gap.' },
  { id: 'tcp-checksum', group: 'L4 · TCP', label: 'Corrupt a checksum', layer: 'transport', fault: 'corrupt', defaultPayload: 4000,
    description: 'One TCP checksum bit is flipped in transit. IPv4 still validates, so TCP itself must discard the segment and recover by retransmitting.' },
  { id: 'tcp-window', group: 'L4 · TCP', label: 'Zero-window recovery', layer: 'transport', fault: 'slow reader', defaultPayload: 4000,
    description: 'Host B has a 256-byte receive buffer and its application pauses reading. The advertised window closes, Host A probes, and transfer resumes when space frees up.' },
  { id: 'tcp-refused', group: 'L4 · TCP', label: 'Closed port / reset', layer: 'transport', fault: 'closed port', defaultPayload: 4000,
    description: 'Nothing listens on the destination port. The SYN is answered with a RST and the connection fails immediately.' },
  { id: 'ping', group: 'L3 · IPv4 & ICMP', label: 'Successful ping', layer: 'network', defaultPayload: 32,
    description: 'An ICMP echo request and reply, preceded by ARP resolving Host B’s MAC address. No transport layer is involved.' },
  { id: 'fragment', group: 'L3 · IPv4 & ICMP', label: 'Fragment & reassemble', layer: 'network', defaultPayload: 4000,
    description: 'The echo datagram is larger than the MTU, so IPv4 splits it into fragments. Compare fragment offsets and MF flags; the receiver reassembles before ICMP sees it.' },
  { id: 'df', group: 'L3 · IPv4 & ICMP', label: 'Oversized packet + DF', layer: 'network', fault: 'DF set', defaultPayload: 4000,
    description: 'The same oversized datagram with Don’t Fragment set. The local send path refuses it instead of fragmenting.' },
  { id: 'checksum', group: 'L3 · IPv4 & ICMP', label: 'Corrupt IPv4 checksum', layer: 'network', fault: 'corrupt', defaultPayload: 32,
    description: 'One IPv4 header checksum bit is flipped. The receiver silently discards the datagram; nothing tells the sender.' },
  { id: 'loss', group: 'L3 · IPv4 & ICMP', label: 'Drop one fragment', layer: 'network', fault: 'drop', defaultPayload: 4000,
    description: 'One non-first fragment is lost. Reassembly can never complete, so the whole datagram is lost even though most bytes arrived.' },
  { id: 'arp-loss', group: 'L3 · IPv4 & ICMP', label: 'Drop ARP replies', layer: 'link', fault: 'drop', defaultPayload: 32,
    description: 'Every ARP reply is dropped. Host A retries, then gives up resolving the neighbor; the IPv4 packet is never sent.' }
];

export const findScenario = (id: string | null) => scenarios.find(scenario => scenario.id === id);
