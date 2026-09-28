import type { SimulationRequest, SimulationResult } from './types';

// The first run also downloads and starts the .NET runtime (a few MB), so allow more than the API's timeout.
const timeoutMs = 60000;

interface Reply { id: number; resultJson?: string; error?: string }

let worker: Worker | undefined;
let nextId = 0;
const pending = new Map<number, { resolve(json: string): void; reject(error: Error): void }>();

function failAll(message: string) {
  worker?.terminate();
  worker = undefined;
  for (const request of pending.values()) request.reject(new Error(message));
  pending.clear();
}

function startWorker() {
  const started = new Worker(new URL('./simulator.worker.ts', import.meta.url), { type: 'module' });
  started.onmessage = ({ data }: MessageEvent<Reply>) => {
    const request = pending.get(data.id);
    if (!request) return;
    pending.delete(data.id);
    if (data.resultJson !== undefined) request.resolve(data.resultJson);
    else request.reject(new Error(`The in-browser TCP.Core runtime failed: ${data.error}`));
  };
  started.onerror = event => {
    event.preventDefault();
    failAll('Could not start the in-browser TCP.Core runtime. Reload the page to try again.');
  };
  return started;
}

/** Runs the experiment on TCP.Core compiled to WebAssembly, in a worker. Same input, output and errors as the API. */
export async function runInBrowser(request: SimulationRequest): Promise<SimulationResult> {
  worker ??= startWorker();
  const id = nextId++;
  const resultJson = await new Promise<string>((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker!.postMessage({ id, requestJson: JSON.stringify(request) });
    setTimeout(() => {
      // A stuck run cannot be interrupted inside the worker; replace the worker instead.
      if (pending.has(id)) failAll('The simulation timed out. Try a smaller payload or a larger MTU.');
    }, timeoutMs);
  });
  const body = JSON.parse(resultJson);
  if ('error' in body) throw new Error(body.error);
  return body as SimulationResult;
}
