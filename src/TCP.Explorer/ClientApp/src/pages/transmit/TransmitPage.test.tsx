import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '../../test/renderRoute';
import type { CapturedFrame, SimulationResult } from './types';

const frame = (number: number, from: 'Host A' | 'Host B', protocol: string, delivery: CapturedFrame['delivery']): CapturedFrame => ({
  number, timeMs: number, from, to: from === 'Host A' ? 'Host B' : 'Host A', protocol, delivery,
  explanation: `Frame ${number} explanation.`, length: 60, sentHex: '48690a', receivedHex: delivery === 'Dropped' ? '' : '48690a',
  fields: [{ name: 'EtherType', value: `value-${number}`, offset: 12, bytes: 2 }],
  sections: [{ name: 'Ethernet header', offset: 0, bytes: 14 }, { name: 'Ethernet padding', offset: 14, bytes: 46 }]
});

const result: SimulationResult = {
  scenario: 'loss', sendAccepted: true, echoAnswered: false, replyVerified: false, outcome: 'Reassembly never completed.',
  payloadBytes: 4000, mtu: 1500, virtualDurationMs: 30000, tcpRetransmissions: 0,
  events: [{ timeMs: 0, kind: 'send', message: 'Echo request sent.' }],
  frames: [frame(1, 'Host A', 'ARP request', 'Delivered'), frame(2, 'Host B', 'ARP reply', 'Delivered'), frame(3, 'Host A', 'IPv4 fragment', 'Dropped')]
};

afterEach(() => vi.restoreAllMocks());

test('a run shows the ladder and inspects the selected frame', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async input =>
    String(input).includes('/api/simulate')
      ? new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } })
      : Promise.reject(new Error('offline')));
  renderRoute('/transmit?scenario=loss');
  await userEvent.click(screen.getByRole('button', { name: 'Run transmission →' }));

  expect(await screen.findByRole('status')).toHaveTextContent('Reassembly never completed.');
  const body = JSON.parse(String(fetchMock.mock.calls.find(([url]) => String(url).includes('simulate'))![1]!.body));
  expect(body).toEqual({ scenario: 'loss', message: 'Hello from TCP.Core!', payloadBytes: 4000, mtu: 1500 });

  const ladder = screen.getByRole('list', { name: 'Captured frames' });
  expect(within(ladder).getAllByRole('button')).toHaveLength(3);
  const dropped = within(ladder).getByRole('button', { name: '#3 IPv4 fragment, Host A to Host B, 60 bytes, dropped' });
  expect(screen.getByRole('heading', { name: '#1 · ARP request · 60 B L2 · Link' })).toBeInTheDocument();

  await userEvent.click(within(ladder).getAllByRole('button')[0]!);
  await userEvent.keyboard('{ArrowDown}');
  expect(screen.getByRole('heading', { name: '#2 · ARP reply · 60 B L2 · Link' })).toBeInTheDocument();
  await userEvent.click(dropped);
  expect(screen.getByText('value-3')).toBeInTheDocument();
  expect(screen.getByRole('heading', { level: 2, name: /^#3 · IPv4 fragment/ })).toHaveTextContent('L3 · Network');

  await userEvent.click(screen.getByRole('button', { name: 'Bytes' }));
  expect(screen.getByText('Sent bytes — never delivered')).toBeInTheDocument();
  expect(screen.getByText((_, element) => element?.tagName === 'PRE' && element.textContent!.startsWith('0000  48 69 0a'))).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Trace' }));
  expect(screen.getByText('Echo request sent.')).toBeInTheDocument();
});

test('editing an input discards a stale capture', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } }));
  renderRoute('/transmit?scenario=loss');
  await userEvent.click(screen.getByRole('button', { name: 'Run transmission →' }));
  await screen.findByRole('list', { name: 'Captured frames' });
  await userEvent.type(screen.getByLabelText('Link MTU'), '0');
  expect(screen.queryByRole('list', { name: 'Captured frames' })).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Inputs changed');
});

test('a host without the API explains how to start it', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('<!doctype html>', { headers: { 'Content-Type': 'text/html' } }));
  renderRoute('/transmit');
  await userEvent.click(screen.getByRole('button', { name: 'Run transmission →' }));
  expect(await screen.findByRole('status')).toHaveTextContent('dotnet run --project src/TCP.Explorer');
});
