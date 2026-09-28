import { useState, type FormEvent, type KeyboardEvent } from 'react';
import { useSearchParams } from 'react-router';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerTag } from '../../components/LayerTag';
import { runSimulation } from './api';
import { CaptureInspector } from './CaptureInspector';
import { findScenario, scenarios, type Scenario } from './scenarios';
import { FrameLadder } from './FrameLadder';
import type { SimulationResult } from './types';
import './transmit.css';

const defaultMessage = 'Hello from TCP.Core!';
const defaultMtu = 1500;
const groups = [...new Set(scenarios.map(scenario => scenario.group))];
const shortcutLabel = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘↵' : 'Ctrl ↵';

export function TransmitPage() {
  useDocumentTitle('Transmit');
  const [searchParams, setSearchParams] = useSearchParams();
  const scenario = findScenario(searchParams.get('scenario')) ?? scenarios[0]!;
  // Keyed by experiment: choosing another one (or arriving via a link) starts from its defaults.
  return <TransmitLab key={scenario.id} scenario={scenario} onChoose={next => setSearchParams({ scenario: next.id }, { replace: true, preventScrollReset: true })} />;
}

type Tone = 'idle' | 'ok' | 'fault' | 'error';
const inputsChanged = 'Inputs changed. Run to capture a fresh exchange.';

function TransmitLab({ scenario, onChoose }: { scenario: Scenario; onChoose: (next: Scenario) => void }) {
  const [message, setMessage] = useState(defaultMessage);
  const [payloadBytes, setPayloadBytes] = useState(scenario.defaultPayload);
  const [mtu, setMtu] = useState(defaultMtu);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<{ text: string; tone: Tone }>({ text: 'Ready. Run the experiment to capture the real exchange between the two hosts.', tone: 'idle' });
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [activeFrame, setActiveFrame] = useState(0);
  const isTcp = scenario.id.startsWith('tcp');

  const invalidate = () => {
    if (!result) return;
    setResult(null);
    setStatus({ text: inputsChanged, tone: 'idle' });
  };

  const run = async (event: FormEvent) => {
    event.preventDefault();
    if (running) return;
    setRunning(true);
    setResult(null);
    setStatus({ text: 'Running TCP.Core on two virtual hosts…', tone: 'idle' });
    try {
      const body = await runSimulation({ scenario: scenario.id, message, payloadBytes, mtu });
      setResult(body);
      setActiveFrame(0);
      // The run's own verdict: the reply or stream arrived intact end to end.
      setStatus({ text: body.outcome, tone: body.replyVerified ? 'ok' : 'fault' });
    } catch (error) {
      setStatus({ text: error instanceof Error ? error.message : String(error), tone: 'error' });
    } finally {
      setRunning(false);
    }
  };

  // ⌘↵ / Ctrl+↵ runs from any input, including the message textarea.
  const onKeyDown = (event: KeyboardEvent<HTMLFormElement>) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      event.currentTarget.requestSubmit();
    }
  };

  return (
    <>
      <PageHeading eyebrow="Observe · Real protocol code · In-memory network" title="Transmit through TCP.Core" next={{ to: '/sizes', label: 'Size things up' }}>
        <p>Two virtual hosts run the actual stack: ARP, IPv4, ICMP and TCP. Pick an experiment, inject a fault, and inspect every frame. No packets leave this app.</p>
      </PageHeading>
      <div className="transmit-bench fill">
        <form className="lab-inputs" onSubmit={run} onKeyDown={onKeyDown}>
          <fieldset className="lab-fields" disabled={running}>
            <div>
              <label htmlFor="scenario">Experiment</label>
              <select id="scenario" value={scenario.id} onChange={event => onChoose(findScenario(event.target.value)!)}>
                {groups.map(group => (
                  <optgroup key={group} label={group}>
                    {scenarios.filter(candidate => candidate.group === group).map(candidate => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
                  </optgroup>
                ))}
              </select>
              <div className="scenario-card">
                <div className="scenario-tags">
                  <LayerTag layer={scenario.layer} />
                  {scenario.fault && <span className="fault-tag">fault: {scenario.fault}</span>}
                </div>
                <p><GlossaryText>{scenario.description}</GlossaryText></p>
              </div>
            </div>
            <div>
              <label htmlFor="transmission-message">Application data <span>UTF-8</span></label>
              <textarea
                id="transmission-message" maxLength={1024} required rows={2} value={message}
                onChange={event => { setMessage(event.target.value); invalidate(); }}
              />
              <details className="lab-note">
                <summary>Repeated or truncated to the payload size</summary>
                <p>
                  Synthetic: large payloads show segmentation. A real app sends only what it writes; routers and switches never add fill. {isTcp
                    ? 'Host B’s demo application echoes the TCP stream, then both close.'
                    : 'This is ICMP echo data; it does not pass through TCP.'}
                </p>
              </details>
            </div>
            <div className="input-pair">
              <div>
                <label htmlFor="transmission-size">Payload bytes</label>
                <input id="transmission-size" type="number" min={1} max={8192} required value={payloadBytes}
                  onChange={event => { setPayloadBytes(event.target.valueAsNumber); invalidate(); }} />
              </div>
              <div>
                <label htmlFor="transmission-mtu">Link MTU</label>
                <input id="transmission-mtu" type="number" min={68} max={9000} required value={mtu}
                  onChange={event => { setMtu(event.target.valueAsNumber); invalidate(); }} />
              </div>
            </div>
          </fieldset>
          <div className="run-bar">
            <button className="primary-button" type="submit" disabled={running}>
              {running ? 'Running…' : result ? 'Run again' : 'Run transmission →'}
              {!running && <kbd aria-hidden="true">{shortcutLabel}</kbd>}
            </button>
            <details className="lab-note">
              <summary>Each run starts fresh</summary>
              <p>Static addresses, empty ARP caches, virtual-second timers (not a latency benchmark). Address claiming, NIC signaling and FCS are outside this experiment.</p>
            </details>
          </div>
        </form>
        <section className="ladder-pane" aria-label="Exchange">
          <div className="ladder-summary">
            <p className={`transmission-status tone-${status.tone}`} role="status">
              {status.tone === 'fault' && <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3z" /><path d="M12 10v4M12 17h.01" /></svg>}
              {status.tone === 'ok' && <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m5 12 5 5L20 7" /></svg>}
              <span>{status.text}</span>
            </p>
            {result && <RunStats result={result} />}
          </div>
          <div className="transmission-hosts">
            <span><strong>Host A</strong> 192.0.2.10</span>
            <span><strong>Host B</strong> 192.0.2.20</span>
          </div>
          {result?.frames.length
            ? <FrameLadder frames={result.frames} activeFrame={activeFrame} onSelect={setActiveFrame} />
            : (
              <div className="ladder-empty">
                {result
                  ? <p>No Ethernet frame was emitted. See the trace for the send result.</p>
                  : running
                    ? <p>Capturing…</p>
                    : <><strong>Frames appear on this ladder</strong><p>One row per Ethernet frame, drawn in the direction it crosses the link. Select a row to inspect it.</p></>}
              </div>
            )}
          <div className="ladder-legend">
            <span className="key-delivered">delivered</span>
            <span className="key-fault">dropped or corrupted</span>
            {!!result?.frames.length && <span className="ladder-keys"><kbd>↑</kbd><kbd>↓</kbd> step frames</span>}
          </div>
        </section>
        {result
          ? <CaptureInspector result={result} activeFrame={activeFrame} onSelect={setActiveFrame} />
          : (
            <div className="packet-inspector inspector-empty">
              <h2>Packet inspector</h2>
              <ul className="inspector-views">
                <li><strong>Fields</strong>Every header field with its value and byte offsets.</li>
                <li><strong>Bytes</strong>The raw frame as a hex dump, before and after any fault.</li>
                <li><strong>Trace</strong>The protocol trace from both hosts, in virtual time.</li>
              </ul>
            </div>
          )}
      </div>
    </>
  );
}

function RunStats({ result }: { result: SimulationResult }) {
  const count = (delivery: string) => result.frames.filter(frame => frame.delivery === delivery).length;
  const dropped = count('Dropped');
  const corrupted = count('Corrupted');
  return (
    <ul className="run-stats" aria-label="Run summary">
      <li>{result.frames.length} frames</li>
      <li className="stat-ok">{count('Delivered')} delivered</li>
      {dropped > 0 && <li className="stat-fault">{dropped} dropped</li>}
      {corrupted > 0 && <li className="stat-fault">{corrupted} corrupted</li>}
      {result.tcpRetransmissions > 0 && <li>{result.tcpRetransmissions} retransmitted</li>}
      <li className="stat-quiet">{result.virtualDurationMs / 1000} virtual s</li>
      <li className="stat-quiet">{result.payloadBytes} B payload</li>
    </ul>
  );
}
