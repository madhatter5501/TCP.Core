import { protocolLayer } from './protocolLayer';

test('frames are tagged with the highest layer they carry', () => {
  expect(protocolLayer('ARP request')).toBe('link');
  expect(protocolLayer('Ethernet')).toBe('link');
  expect(protocolLayer('IPv4 fragment · offset 1480 B')).toBe('network');
  expect(protocolLayer('ICMP echo reply')).toBe('network');
  expect(protocolLayer('TCP SYN, ACK')).toBe('transport');
});
