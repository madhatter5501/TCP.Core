import { useEffect, useState } from 'react';

export interface TransportInfo { mode: string; endpoint: string }

/** Which transport served this page, so live TCP.Core traffic is not mistaken for the simulations. */
export function useTransportStatus() {
  const [transport, setTransport] = useState<TransportInfo | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/transport', { cache: 'no-store', signal: controller.signal })
      .then(response => (response.ok && response.headers.get('content-type')?.includes('json') ? response.json() : null))
      .then(setTransport)
      // Status is informational; the page works without it.
      .catch(() => {});
    return () => controller.abort();
  }, []);
  return transport;
}
