import type { SimulationRequest } from './types';

const request: SimulationRequest = { scenario: 'ping', message: 'Hi', payloadBytes: 32, mtu: 1500 };

/** Stands in for simulator.worker.ts: answers each message with whatever the test queues. */
class FakeWorker {
  static instances: FakeWorker[] = [];
  static reply: (requestJson: string) => { resultJson?: string; error?: string } = () => ({});
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  received: string[] = [];
  terminated = false;
  constructor() { FakeWorker.instances.push(this); }
  postMessage({ id, requestJson }: { id: number; requestJson: string }) {
    this.received.push(requestJson);
    queueMicrotask(() => this.onmessage?.({ data: { id, ...FakeWorker.reply(requestJson) } } as MessageEvent));
  }
  terminate() { this.terminated = true; }
}

async function load() {
  vi.resetModules();
  FakeWorker.instances = [];
  vi.stubGlobal('Worker', FakeWorker);
  return (await import('./browserSimulator')).runInBrowser;
}

afterEach(() => vi.unstubAllGlobals());

test('sends the request JSON to one reused worker and returns its result', async () => {
  const runInBrowser = await load();
  FakeWorker.reply = () => ({ resultJson: JSON.stringify({ scenario: 'ping', replyVerified: true }) });
  await expect(runInBrowser(request)).resolves.toMatchObject({ replyVerified: true });
  await runInBrowser(request);
  expect(FakeWorker.instances).toHaveLength(1);
  expect(JSON.parse(FakeWorker.instances[0]!.received[0]!)).toEqual(request);
});

test('invalid input rejects with the simulation message, as the API does', async () => {
  const runInBrowser = await load();
  FakeWorker.reply = () => ({ resultJson: JSON.stringify({ error: 'MTU must be between 68 and 9000 bytes.' }) });
  await expect(runInBrowser(request)).rejects.toThrow('MTU must be between 68 and 9000 bytes.');
});

test('a runtime failure is reported, not rendered as a result', async () => {
  const runInBrowser = await load();
  FakeWorker.reply = () => ({ error: 'dotnet.js not found' });
  await expect(runInBrowser(request)).rejects.toThrow('The in-browser TCP.Core runtime failed: dotnet.js not found');
});

test('a worker that cannot start fails the run and is replaced next time', async () => {
  const runInBrowser = await load();
  FakeWorker.reply = () => ({});
  const run = runInBrowser(request);
  FakeWorker.instances[0]!.onerror!(new Event('error'));
  await expect(run).rejects.toThrow('Could not start the in-browser TCP.Core runtime');
  expect(FakeWorker.instances[0]!.terminated).toBe(true);
  FakeWorker.reply = () => ({ resultJson: '{}' });
  await runInBrowser(request);
  expect(FakeWorker.instances).toHaveLength(2);
});
