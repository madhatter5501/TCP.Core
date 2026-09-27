import { useState } from 'react';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerTag } from '../../components/LayerTag';
import { Term } from '../../components/Term';
import { hexDump } from './hexDump';
import { protocolLayer } from './protocolLayer';
import type { SimulationResult } from './types';

const views = [['fields', 'Fields'], ['bytes', 'Bytes'], ['trace', 'Trace']] as const;
type View = (typeof views)[number][0];

export function CaptureInspector({ result, activeFrame }: { result: SimulationResult; activeFrame: number }) {
  const [view, setView] = useState<View>('fields');
  const frame = result.frames[activeFrame];
  // With no frames, only the trace has anything to show.
  const shown: View = frame ? view : 'trace';
  return (
    <div className="packet-inspector">
      <div className="inspector-top">
        <h2>{frame ? <>#{frame.number} · {frame.protocol} · {frame.length} B <LayerTag layer={protocolLayer(frame.protocol)} /></> : 'No frames emitted'}</h2>
        <div className="segmented" role="group" aria-label="Inspector view">
          {views.map(([id, label]) => (
            <button key={id} type="button" aria-pressed={shown === id} disabled={!frame && id !== 'trace'} onClick={() => setView(id)}>{label}</button>
          ))}
        </div>
      </div>
      <div className="inspector-body">
        {shown === 'fields' && frame && (
          <>
            <p className="muted">{frame.from} → {frame.to}. <GlossaryText>{frame.explanation}</GlossaryText> Offsets are zero-based from the first byte of the Ethernet frame; <Term id="fcs" /> and <Term id="preamble">preamble</Term> are absent.</p>
            <table className="field-table">
              <thead><tr><th>Field</th><th>Value</th><th>Bytes</th></tr></thead>
              <tbody>
                {frame.fields.map(field => (
                  <tr key={`${field.offset}-${field.name}`}><td>{field.name}</td><td>{field.value}</td><td>{field.offset}–{field.offset + field.bytes - 1}</td></tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {shown === 'bytes' && frame && (
          <>
            <h3>{frame.delivery === 'Dropped' ? 'Sent bytes — never delivered' : 'Bytes delivered to the receiver'}</h3>
            <pre>{hexDump(frame.receivedHex || frame.sentHex)}</pre>
            {frame.delivery === 'Corrupted' && (
              <>
                <h3>Original bytes before corruption</h3>
                <pre>{hexDump(frame.sentHex)}</pre>
              </>
            )}
          </>
        )}
        {shown === 'trace' && (
          <div className="execution-trace">
            {result.events.map((entry, index) => (
              <p key={index}><code>{entry.timeMs / 1000}s · {entry.kind}</code><br />{entry.message}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
