/// <reference lib="webworker" />
// Runs TransmissionSimulation.cs, compiled to WebAssembly by src/TCP.Explorer.Browser, off the page's main thread.
// Static builds copy that project's _framework/ next to index.html.

interface SimulationExports { TCP: { Explorer: { BrowserSimulation: { Simulate(requestJson: string): string } } } }
interface DotnetRuntime {
  getConfig(): { mainAssemblyName?: string };
  getAssemblyExports(assemblyName: string): Promise<SimulationExports>;
}

let simulate: Promise<(requestJson: string) => string> | undefined;

async function load() {
  const url = `${import.meta.env.BASE_URL}_framework/dotnet.js`;
  const { dotnet } = await import(/* @vite-ignore */ url);
  const runtime: DotnetRuntime = await dotnet.create();
  const exports = await runtime.getAssemblyExports(runtime.getConfig().mainAssemblyName!);
  return (requestJson: string) => exports.TCP.Explorer.BrowserSimulation.Simulate(requestJson);
}

// addEventListener, not self.onmessage: with an onmessage handler set, the .NET runtime's dotnet.create()
// never resolves inside a worker (seen with .NET 10.0).
self.addEventListener('message', async (event: MessageEvent<{ id: number; requestJson: string }>) => {
  const { id, requestJson } = event.data;
  try {
    simulate ??= load();
    self.postMessage({ id, resultJson: (await simulate)(requestJson) });
  } catch (error) {
    self.postMessage({ id, error: error instanceof Error ? error.message : String(error) });
  }
});
