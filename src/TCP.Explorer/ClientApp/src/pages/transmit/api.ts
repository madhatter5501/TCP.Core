import type { SimulationRequest, SimulationResult } from './types';

const timeoutMs = 15000;

/** Runs the experiment on the ASP.NET host. The browser renders returned evidence and never fabricates it. */
export async function runSimulation(request: SimulationRequest): Promise<SimulationResult> {
  let response: Response;
  try {
    response = await fetch(`${import.meta.env.BASE_URL}api/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(timeoutMs)
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'TimeoutError') throw new Error('The server timed out. Try again after checking the local app is running.');
    throw new Error('Could not reach the Explorer host. Start it with `dotnet run --project src/TCP.Explorer`.');
  }
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
    throw new Error('Real-code transmissions need the ASP.NET host. Start it with `dotnet run --project src/TCP.Explorer`.');
  }
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? 'The simulation could not run.');
  return body as SimulationResult;
}
