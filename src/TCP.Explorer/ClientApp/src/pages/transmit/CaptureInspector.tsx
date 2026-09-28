import { useState, type CSSProperties } from 'react';
import { layers } from '../../content/layers';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerTag } from '../../components/LayerTag';
import { Term } from '../../components/Term';
import { hexDump } from './hexDump';
import { protocolLayer } from './protocolLayer';
import type { FrameSection, SimulationResult } from './types';

const views = [['fields', 'Fields'], ['bytes', 'Bytes'], ['trace', 'Trace']] as const;
type View = (typeof views)[number][0];

const layerColor = (slug: string) => layers.find(layer => layer.slug === slug)!.color;

/** Byte-map color for a frame section: its layer's color, payload in the application color, padding neutral. */
function sectionColor(name: string) {
  if (name === 'Ethernet padding') return 'var(--padding)';
  if (name.startsWith('Ethernet') || name.startsWith('ARP')) return layerColor('link');
  if (name.startsWith('IPv4') || name.startsWith('ICMP header')) return layerColor('network');
  if (name.startsWith('TCP header')) return layerColor('transport');
  return layerColor('application');
}

/** Section colors, with a section that follows one of the same color drawn lighter so the two stay apart. */
function sectionColors(sections: FrameSection[]) {
  const colors = sections.map(section => sectionColor(section.name));
  return colors.map((color, index) => index > 0 && colors[index - 1] === color ? `color-mix(in srgb, ${color} 55%, var(--panel))` : color);
}

export function CaptureInspector({ result, activeFrame, onSelect }: { result: SimulationResult; activeFrame: number; onSelect: (index: number) => void }) {
  const [view, setView] = useState<View>('fields');
  const frame = result.frames[activeFrame];
  // With no frames, only the trace has anything to show.
  const shown: View = frame ? view : 'trace';
  const colors = frame ? sectionColors(frame.sections) : [];
  const colorAt = (offset: number) => colors[frame!.sections.findIndex(section => offset >= section.offset && offset < section.offset + section.bytes)];
  return (
    <div className="packet-inspector">
      <div className="inspector-head">
        <div className="inspector-top">
          <div>
            <h2>{frame ? <>#{frame.number} · {frame.protocol} · {frame.length} B <LayerTag layer={protocolLayer(frame.protocol)} /></> : 'No frames emitted'}</h2>
            {frame && (
              <p className="frame-route">
                {frame.from} → {frame.to} · t = {(frame.timeMs / 1000).toFixed(3)}s
                <span className={`delivery-chip ${frame.delivery.toLowerCase()}`}>{frame.delivery}</span>
              </p>
            )}
          </div>
          <div className="inspector-controls">
            {frame && (
              <div className="frame-stepper">
                <button type="button" aria-label="Previous frame" disabled={activeFrame === 0} onClick={() => onSelect(activeFrame - 1)}>
                  <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m18 15-6-6-6 6" /></svg>
                </button>
                <button type="button" aria-label="Next frame" disabled={activeFrame === result.frames.length - 1} onClick={() => onSelect(activeFrame + 1)}>
                  <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6" /></svg>
                </button>
              </div>
            )}
            <div className="segmented" role="group" aria-label="Inspector view">
              {views.map(([id, label]) => (
                <button key={id} type="button" aria-pressed={shown === id} disabled={!frame && id !== 'trace'} onClick={() => setView(id)}>{label}</button>
              ))}
            </div>
          </div>
        </div>
        {frame && (
          <figure className="byte-map" aria-label={`Byte map of the ${frame.length}-byte frame`}>
            <div className="byte-map-bar" aria-hidden="true">
              {frame.sections.map((section, index) => (
                <span key={section.offset} style={{ flexGrow: section.bytes, background: colors[index] }} title={`${section.name}: bytes ${section.offset}–${section.offset + section.bytes - 1}`} />
              ))}
            </div>
            <figcaption>
              {frame.sections.map((section, index) => (
                <span key={section.offset}><i style={{ background: colors[index] } as CSSProperties} />{section.name} <span className="muted">{section.offset}–{section.offset + section.bytes - 1}</span></span>
              ))}
            </figcaption>
          </figure>
        )}
      </div>
      <div className="inspector-body">
        {shown === 'fields' && frame && (
          <>
            <p className="muted"><GlossaryText>{frame.explanation}</GlossaryText> Offsets are zero-based from the first byte of the Ethernet frame; <Term id="fcs" /> and <Term id="preamble">preamble</Term> are absent.</p>
            <table className="field-table">
              <thead><tr><th>Field</th><th>Value</th><th>Bytes</th></tr></thead>
              <tbody>
                {frame.fields.map(field => (
                  <tr key={`${field.offset}-${field.name}`}><td><i className="field-dot" style={{ background: colorAt(field.offset) }} />{field.name}</td><td>{field.value}</td><td>{field.offset}–{field.offset + field.bytes - 1}</td></tr>
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
