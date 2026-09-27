import { hexDump } from './hexDump';

test('formats offsets, padded hex columns and printable ASCII', () => {
  const hex = [...new TextEncoder().encode('Hello, TCP.Core!\u0001')].map(byte => byte.toString(16).padStart(2, '0')).join('');
  expect(hexDump(hex).split('\n')).toEqual([
    '0000  48 65 6c 6c 6f 2c 20 54 43 50 2e 43 6f 72 65 21  Hello, TCP.Core!',
    '0010  01                                               .'
  ]);
});
