import type { LayerSlug } from '../../content/layers';

/**
 * The highest layer a captured frame carries, from the protocol label TransmissionSimulation assigns
 * ("ARP request", "IPv4 fragment · offset 1480 B", "TCP SYN", "ICMP echo reply", "Ethernet").
 */
export function protocolLayer(protocol: string): LayerSlug {
  if (protocol.startsWith('TCP')) return 'transport';
  if (protocol.startsWith('IPv4') || protocol.startsWith('ICMP')) return 'network';
  return 'link';
}
