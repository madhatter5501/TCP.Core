/** Pure IPv4/TCP/Ethernet byte accounting for the MTU & MSS lab. No DOM, no React. */

export interface SizeInput {
  mtu: number;
  pathMtu: number;
  peerMss: number;
  ipOptions: number;
  tcpOptions: number;
  dataSize: number;
  vlan: boolean;
}

export interface SizeResult {
  effectiveMtu: number;
  advertisedMss: number;
  capacity: number;
  firstData: number;
  ipHeader: number;
  tcpHeader: number;
  ipLength: number;
  ethernetHeader: number;
  padding: number;
  frameWithoutFcs: number;
  frameWithFcs: number;
  segments: number;
  lastData: number;
}

export interface FragmentPiece {
  /** Offset in 8-byte units, exactly as carried in the IPv4 header. */
  offset: number;
  bytes: number;
  total: number;
  more: boolean;
}

export interface FragmentResult {
  blocked: boolean;
  pieces: FragmentPiece[];
}

export const fixedIpHeader = 20;
export const fixedTcpHeader = 20;
export const fcsBytes = 4;
const minimumFrameWithoutFcs = 60;

export const defaultSizeInput: SizeInput = { mtu: 1500, pathMtu: 1500, peerMss: 1460, ipOptions: 0, tcpOptions: 0, dataSize: 4000, vlan: false };

export function calculate(input: SizeInput): SizeResult {
  const { mtu, pathMtu, peerMss, ipOptions, tcpOptions, dataSize, vlan } = input;
  const limits: [string, number, number, number][] = [
    ['Link MTU', mtu, 68, 9000], ['Path MTU', pathMtu, 68, 9000],
    ['Peer MSS', peerMss, 1, 65495], ['Application data', dataSize, 1, 60000],
    ['IPv4 options', ipOptions, 0, 40], ['TCP options', tcpOptions, 0, 40]
  ];
  for (const [name, value, min, max] of limits) {
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be a whole number from ${min} to ${max}.`);
  }
  if (ipOptions % 4 || tcpOptions % 4) throw new Error('Header options must be padded to a multiple of four bytes.');
  const effectiveMtu = Math.min(mtu, pathMtu);
  const capacity = Math.max(0, Math.min(effectiveMtu - fixedIpHeader - fixedTcpHeader, peerMss) - ipOptions - tcpOptions);
  const firstData = Math.min(dataSize, capacity);
  const ipHeader = fixedIpHeader + ipOptions;
  const tcpHeader = fixedTcpHeader + tcpOptions;
  const ipLength = ipHeader + tcpHeader + firstData;
  const ethernetHeader = vlan ? 18 : 14;
  // Match EthernetFrame.Serialize: at least 60 bytes, excluding the FCS.
  const padding = Math.max(0, minimumFrameWithoutFcs - ethernetHeader - ipLength);
  const frameWithoutFcs = ethernetHeader + ipLength + padding;
  return {
    effectiveMtu, advertisedMss: mtu - fixedIpHeader - fixedTcpHeader, capacity, firstData, ipHeader, tcpHeader,
    ipLength, ethernetHeader, padding, frameWithoutFcs, frameWithFcs: frameWithoutFcs + fcsBytes,
    segments: capacity ? Math.ceil(dataSize / capacity) : 0,
    lastData: capacity ? ((dataSize - 1) % capacity) + 1 : 0
  };
}

export function fragment(payloadLength: number, mtu: number, dontFragment: boolean): FragmentResult {
  if (!Number.isInteger(payloadLength) || payloadLength < 1 || payloadLength > 65515 || !Number.isInteger(mtu) || mtu < 68 || mtu > 65535) {
    throw new Error('Invalid IPv4 fragmentation input.');
  }
  if (payloadLength + fixedIpHeader <= mtu) return { blocked: false, pieces: [{ offset: 0, bytes: payloadLength, total: payloadLength + fixedIpHeader, more: false }] };
  if (dontFragment) return { blocked: true, pieces: [] };
  const chunk = Math.floor((mtu - fixedIpHeader) / 8) * 8;
  const pieces: FragmentPiece[] = [];
  for (let offset = 0; offset < payloadLength; offset += chunk) {
    const bytes = Math.min(chunk, payloadLength - offset);
    pieces.push({ offset: offset / 8, bytes, total: bytes + fixedIpHeader, more: offset + bytes < payloadLength });
  }
  return { blocked: false, pieces };
}
