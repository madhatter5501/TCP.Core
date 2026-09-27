import { useRef, useState, type KeyboardEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { headerVariants, type Layer } from '../../content/layers';
import { GlossaryText } from '../../components/GlossaryText';

export const layerViews = [
  { slug: 'overview', label: 'Overview' },
  { slug: 'headers', label: 'PDU & bits' },
  { slug: 'gotchas', label: 'Gotchas' },
  { slug: 'code', label: 'In the code' }
] as const;

export type LayerView = (typeof layerViews)[number]['slug'];

export function LayerInspector({ layer, view }: { layer: Layer; view: LayerView }) {
  const navigate = useNavigate();
  const tabs = useRef<(HTMLAnchorElement | null)[]>([]);
  const index = layerViews.findIndex(candidate => candidate.slug === view);

  // Roving focus across the tabs, as in the WAI-ARIA tabs pattern. Each tab is also a real link.
  const onKeyDown = (event: KeyboardEvent) => {
    const count = layerViews.length;
    const next = { ArrowRight: (index + 1) % count, ArrowLeft: (index + count - 1) % count, Home: 0, End: count - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    navigate(`/layers/${layer.slug}/${layerViews[next]!.slug}`, { replace: true, preventScrollReset: true });
    tabs.current[next]?.focus();
  };

  return (
    <aside className="inspector" aria-label="Layer details">
      <div className="inspector-heading">
        <span className="eyebrow" style={{ color: layer.color }}>{layer.number} / {layer.osi}</span>
        <span className={`status-badge${layer.status === 'Planned' ? ' planned' : ''}`}>{layer.status}</span>
      </div>
      <h2>{layer.name}</h2>
      <p className="layer-subtitle">{layer.subtitle}</p>
      <div className="detail-tabs" role="tablist" aria-label="Layer detail view" onKeyDown={onKeyDown}>
        {layerViews.map((tab, i) => (
          <Link
            key={tab.slug}
            ref={element => { tabs.current[i] = element; }}
            to={`/layers/${layer.slug}/${tab.slug}`}
            replace
            preventScrollReset
            role="tab"
            id={`tab-${tab.slug}`}
            aria-selected={tab.slug === view}
            aria-controls="detail-content"
            tabIndex={tab.slug === view ? 0 : -1}
          >
            {tab.label}
          </Link>
        ))}
      </div>
      <div id="detail-content" className="detail-content" role="tabpanel" aria-labelledby={`tab-${view}`} tabIndex={0}>
        {view === 'overview' && <Overview layer={layer} />}
        {view === 'headers' && <Headers key={layer.slug} layer={layer} />}
        {view === 'gotchas' && layer.gotchas.map(gotcha => (
          <div className="gotcha" key={gotcha.title}><strong>{gotcha.title}</strong><p><GlossaryText>{gotcha.description}</GlossaryText></p></div>
        ))}
        {view === 'code' && (
          <>
            <p>Paths below are relative to <code>src/TCP.Core/</code>. These are a map to the source, not simulated implementations.</p>
            {layer.files.map(file => <div className="source-item" key={file.path}><code>{file.path}</code><p>{file.description}</p></div>)}
          </>
        )}
      </div>
    </aside>
  );
}

function Overview({ layer }: { layer: Layer }) {
  return (
    <>
      <div className="pdu-pill"><span>PDU</span><strong>{layer.pdu}</strong></div>
      <h3>What it does</h3>
      <p><GlossaryText>{layer.purpose}</GlossaryText></p>
      <h3>Why this layer exists</h3>
      <p><GlossaryText>{layer.why}</GlossaryText></p>
      <ul className="part-list">
        {layer.parts.map(part => <li key={part.name}><strong>{part.name}</strong><GlossaryText>{part.description}</GlossaryText></li>)}
      </ul>
    </>
  );
}

function Headers({ layer }: { layer: Layer }) {
  const variants = headerVariants[layer.slug];
  const [protocol, setProtocol] = useState(variants?.[0]?.protocol);
  const variant = variants?.find(candidate => candidate.protocol === protocol);
  const fields = variant?.fields ?? layer.fields;
  const note = variant?.note ?? layer.pduNote;
  return (
    <>
      {variants && (
        <div className="protocol-choice" role="group" aria-label="Header protocol">
          {variants.map(candidate => (
            <button key={candidate.protocol} aria-pressed={candidate.protocol === protocol} onClick={() => setProtocol(candidate.protocol)}>
              {candidate.protocol}
            </button>
          ))}
        </div>
      )}
      <p><GlossaryText>{note}</GlossaryText></p>
      <table className="field-table">
        <thead><tr><th>Field</th><th>Bits</th><th>Why it’s here</th></tr></thead>
        <tbody>{fields.map(field => <tr key={field.name}><td>{field.name}</td><td>{field.bits}</td><td><GlossaryText>{field.purpose}</GlossaryText></td></tr>)}</tbody>
      </table>
    </>
  );
}
