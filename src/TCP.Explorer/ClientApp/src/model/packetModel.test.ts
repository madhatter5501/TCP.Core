import { calculate, defaultSizeInput as example, fragment } from './packetModel';

test('Ethernet/IPv4/TCP known example: 1460 data, three segments, 1518-byte frame', () => {
  const value = calculate(example);
  expect(value.advertisedMss).toBe(1460);
  expect(value.capacity).toBe(1460);
  expect(value.segments).toBe(3);
  expect(value.lastData).toBe(1080);
  expect(value.ipLength).toBe(1500);
  expect(value.frameWithoutFcs).toBe(1514);
  expect(value.frameWithFcs).toBe(1518);
});

test('options shrink data without shrinking the advertised fixed-header MSS example', () => {
  const value = calculate({ ...example, tcpOptions: 12 });
  expect(value.advertisedMss).toBe(1460);
  expect(value.capacity).toBe(1448);
  expect(value.ipLength).toBe(1500);
  expect(calculate({ ...example, pathMtu: 1400, tcpOptions: 12 }).capacity).toBe(1348);
  expect(calculate({ ...example, peerMss: 1200, ipOptions: 4, tcpOptions: 12 }).capacity).toBe(1184);
});

test('VLAN adds four bytes to full frames while small frames use codec padding', () => {
  expect(calculate({ ...example, vlan: true }).frameWithFcs).toBe(1522);
  for (const vlan of [false, true]) {
    const value = calculate({ ...example, dataSize: 1, vlan });
    expect(value.frameWithFcs).toBe(64);
    expect(value.ethernetHeader + value.ipLength + value.padding).toBe(60);
  }
});

test('exact boundaries, jumbo and impossible header budgets', () => {
  expect(calculate({ ...example, dataSize: 1460 }).segments).toBe(1);
  expect(calculate({ ...example, dataSize: 1461 }).lastData).toBe(1);
  expect(calculate({ ...example, mtu: 9000, pathMtu: 9000, peerMss: 8960 }).capacity).toBe(8960);
  expect(calculate({ ...example, mtu: 68, ipOptions: 40, tcpOptions: 40 }).capacity).toBe(0);
});

test('invalid and nonfinite inputs never produce plausible-looking results', () => {
  for (const changes of [{ mtu: NaN }, { mtu: 67 }, { pathMtu: 9001 }, { dataSize: 0 }, { dataSize: Infinity }, { peerMss: 1.5 }, { ipOptions: 3 }]) {
    expect(() => calculate({ ...example, ...changes })).toThrow();
  }
});

test('known fragments preserve the payload and eight-byte offsets', () => {
  expect(fragment(4020, 1500, false).pieces).toEqual([
    { offset: 0, bytes: 1480, total: 1500, more: true },
    { offset: 185, bytes: 1480, total: 1500, more: true },
    { offset: 370, bytes: 1060, total: 1080, more: false }
  ]);
  expect(fragment(4020, 1500, true).blocked).toBe(true);
  expect(fragment(1480, 1500, true).pieces).toHaveLength(1);
});

test('fragmentation conserves data across small, odd and jumbo MTUs', () => {
  for (const mtu of [68, 69, 576, 1492, 1500, 1501, 9000]) {
    for (const payload of [1, 48, 49, 1480, 1481, 4020, 60060]) {
      const { pieces } = fragment(payload, mtu, false);
      let covered = 0;
      for (const [index, piece] of pieces.entries()) {
        expect(piece.offset * 8).toBe(covered);
        expect(piece.total).toBeLessThanOrEqual(mtu);
        expect(piece.more).toBe(index < pieces.length - 1);
        if (piece.more) expect(piece.bytes % 8).toBe(0);
        covered += piece.bytes;
      }
      expect(covered).toBe(payload);
    }
  }
});
