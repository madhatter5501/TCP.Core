import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { GlossaryText } from '../../components/GlossaryText';
import { runSimulation } from './api';
import { CaptureInspector } from './CaptureInspector';
import { findScenario, scenarios, type Scenario } from './scenarios';
import { FrameLadder } from './FrameLadder';
import type { SimulationResult } from './types';
import './transmit.css';

const defaultMessage = 'Hello from TCP.Core!';
const defaultMtu = 1500;
const groups = [...new Set(scenarios.map(scenario => scenario.group))];

export function TransmitPage() {
  useDocumentTitle('Transmit');
  const [searchParams, setSearchParams] = useSearchParams();
  const scenario = findScenario(searchParams.get('scenario')) ?? scenarios[0]!;
  // Keyed by experiment: choosing another one (or arriving via a link) starts from its defaults.
  return <TransmitLab key={scenario.id} scenario={scenario} onChoose={next => setSearchParams({ scenario: next.id }, { replace: true, preventScrollReset: true })} />;
}

function TransmitLab({ scenario, onChoose }: { scenario: Scenario; onChoose: (next: Scenario) => void }) {
  const [message, setMessage] = useState(defaultMessage);
  const [payloadBytes, setPayloadBytes] = useState(scenario.defaultPayload);
  const [mtu, setMtu] = useState(defaultMtu);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState('Run an experiment to capture the actual exchange.');
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [activeFrame, setActiveFrame] = useState(0);
  const isTcp = scenario.id.startsWith('tcp');

  const invalidate = (why: string) => {
    if (!result) return;
    setResult(null);
    setStatus(why);
  };

  const run = async (event: FormEvent) => {
    event.preventDefault();
    if (running) return;
    setRunning(true);
    setResult(null);
    setStatus('Running TCP.Core on two virtual hosts…');
    try {
      const body = await runSimulation({ scenario: scenario.id, message, payloadBytes, mtu });
      setResult(body);
      setActiveFrame(0);
      setStatus(body.outcome);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <PageHeading eyebrow="Observe · Real protocol code · In-memory network" title="Transmit through TCP.Core" next={{ to: '/sizes', label: 'Size things up' }}>
        <p>Two virtual hosts run the actual stack: ARP, IPv4, ICMP and TCP. Pick an experiment, inject a fault, and inspect every frame. No packets leave this app.</p>
      </PageHeading>
      <div className="transmit-bench fill">
        <form className="lab-inputs" onSubmit={run}>
          <fieldset disabled={running}>
            <label htmlFor="scenario">Experiment</label>
            <select id="scenario" value={scenario.id} onChange={event => onChoose(findScenario(event.target.value)!)}>
              {groups.map(group => (
                <optgroup key={group} label={group}>
                  {scenarios.filter(candidate => candidate.group === group).map(candidate => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
                </optgroup>
              ))}
            </select>
            <p className="scenario-description"><GlossaryText>{scenario.description}</GlossaryText></p>
            <label htmlFor="transmission-message">Application data (UTF-8)</label>
            <textarea
              id="transmission-message" maxLength={1024} required rows={2} value={message}
              onChange={event => { setMessage(event.target.value); invalidate('Inputs changed. Run to capture a fresh exchange.'); }}
            />
            <p className="small-muted">
              Synthetic: the sending app writes this text repeated or truncated to the payload size, so large payloads show segmentation. A real app sends only what it writes; routers and switches never add fill. {isTcp
                ? 'Host B’s demo application echoes the TCP stream, then both close.'
                : 'This is ICMP echo data; it does not pass through TCP.'}
            </p>
            <div className="input-pair">
              <div>
                <label htmlFor="transmission-size">Bytes the app writes</label>
                <input id="transmission-size" type="number" min={1} max={8192} required value={payloadBytes}
                  onChange={event => { setPayloadBytes(event.target.valueAsNumber); invalidate('Inputs changed. Run to capture a fresh exchange.'); }} />
              </div>
              <div>
                <label htmlFor="transmission-mtu">Link MTU</label>
                <input id="transmission-mtu" type="number" min={68} max={9000} required value={mtu}
                  onChange={event => { setMtu(event.target.valueAsNumber); invalidate('Inputs changed. Run to capture a fresh exchange.'); }} />
              </div>
            </div>
            <button className="primary-button" type="submit">{running ? 'Running…' : 'Run transmission →'}</button>
          </fieldset>
          <p className="small-muted transmission-scope">Each run starts fresh: static addresses, empty ARP caches, virtual-second timers (not a latency benchmark). Address claiming, NIC signaling and FCS are outside this experiment.</p>
        </form>
        <section className="ladder-pane" aria-label="Exchange">
          <p className="transmission-status" role="status">{status}</p>
          <div className="transmission-hosts">
            <span><strong>Host A</strong> 192.0.2.10</span>
            <span><strong>Host B</strong> 192.0.2.20</span>
          </div>
          {result?.frames.length
            ? <FrameLadder frames={result.frames} activeFrame={activeFrame} onSelect={setActiveFrame} />
            : <div className="ladder-empty">{result ? 'No Ethernet frame was emitted. See the trace for the send result.' : running ? 'Capturing…' : 'Frames appear here after a run. Select one to inspect it.'}</div>}
          {result && (
            <div className="result-line">
              <strong>{result.frames.length} frames</strong>
              <span>{result.virtualDurationMs / 1000} virtual s · {result.payloadBytes} payload B</span>
            </div>
          )}
        </section>
        {result
          ? <CaptureInspector result={result} activeFrame={activeFrame} />
          : (
            <div className="packet-inspector inspector-empty">
              <h2>Packet inspector</h2>
              <p className="muted">After a run, pick a frame to see every header field with its value and byte offsets, the raw bytes as a hex dump, and the protocol trace from both hosts.</p>
              <p className="muted">Colors: <span className="key-delivered">delivered</span> · <span className="key-fault">dropped or corrupted</span>.</p>
            </div>
          )}
      </div>
    </>
  );
}
