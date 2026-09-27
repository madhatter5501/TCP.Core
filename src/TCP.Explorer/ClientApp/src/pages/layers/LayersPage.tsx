import { useEffect, useState, type CSSProperties } from 'react';
import { useNavigate, useParams } from 'react-router';
import { layers } from '../../content/layers';
import { NotFoundPage } from '../../app/NotFoundPage';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerInspector, layerViews, type LayerView } from './LayerInspector';
import { StackCanvas, type Direction } from './StackCanvas';
import './layers.css';

const walkthroughDelayMs = 2400;

export function LayersPage() {
  const params = useParams();
  const navigate = useNavigate();
  const [direction, setDirection] = useState<Direction>('send');
  const [playing, setPlaying] = useState(false);
  const selected = layers.findIndex(layer => layer.slug === params.layer);
  const view = (params.view ?? 'overview') as LayerView;
  const layer = layers[selected];
  const validView = layerViews.some(candidate => candidate.slug === view);
  useDocumentTitle(layer ? `${layer.number} ${layer.name}` : 'Layers');

  const last = direction === 'send' ? layers.length - 1 : 0;
  const first = direction === 'send' ? 0 : layers.length - 1;
  const go = (index: number, replace = false) =>
    navigate(`/layers/${layers[index]!.slug}${view === 'overview' ? '' : `/${view}`}`, { replace, preventScrollReset: true });
  const step = () => go((selected + (direction === 'send' ? 1 : -1) + layers.length) % layers.length, playing);

  useEffect(() => {
    if (!playing) return;
    if (selected === last) { setPlaying(false); return; }
    const timer = setTimeout(step, walkthroughDelayMs);
    return () => clearTimeout(timer);
  });

  useEffect(() => {
    const pause = () => { if (document.hidden) setPlaying(false); };
    document.addEventListener('visibilitychange', pause);
    return () => document.removeEventListener('visibilitychange', pause);
  }, []);

  if (!layer || !validView) return <NotFoundPage />;

  const choose = (index: number) => { setPlaying(false); go(index); };
  const changeDirection = (next: Direction) => {
    setPlaying(false);
    setDirection(next);
    go(next === 'send' ? 0 : layers.length - 1);
  };

  return (
    <>
      <PageHeading eyebrow="Understand · Encapsulation" title="Walk the layers" next={{ to: '/transmit', label: 'Transmit real packets' }}>
        <p>Each layer wraps what it receives from above in its own header. Pick a layer, or walk the whole journey out and back in.</p>
      </PageHeading>
      <section className="workbench fill" aria-label="Interactive stack explorer">
        <div className="diagram-panel">
          <div className="diagram-controls">
            <div className="segmented" aria-label="Direction">
              <button aria-pressed={direction === 'send'} onClick={() => changeDirection('send')}>↓ Send</button>
              <button aria-pressed={direction === 'receive'} onClick={() => changeDirection('receive')}>↑ Receive</button>
            </div>
            <div className="playback">
              <button
                className="quiet-button"
                aria-pressed={playing}
                onClick={() => {
                  if (playing) { setPlaying(false); return; }
                  go(first, true);
                  setPlaying(true);
                }}
              >
                {playing ? 'Ⅱ Pause' : '▶ Walk through'}
              </button>
              <button className="quiet-button" aria-label="Next layer" onClick={() => { setPlaying(false); step(); }}>Step →</button>
            </div>
          </div>
          <div className="canvas-shell">
            <StackCanvas selected={selected} direction={direction} onSelect={choose} />
          </div>
          <div className="layer-buttons" role="group" aria-label="Select layer">
            {layers.map((candidate, index) => (
              <button
                key={candidate.slug}
                style={{ '--layer-color': candidate.color } as CSSProperties}
                aria-pressed={index === selected}
                aria-label={`Explore ${candidate.number} ${candidate.name}`}
                onClick={() => choose(index)}
              >
                {candidate.number}
              </button>
            ))}
          </div>
          <div className="diagram-caption">
            <span className="caption-mark" aria-hidden="true">↳</span>
            <p aria-live="polite"><GlossaryText>{layer[direction]}</GlossaryText></p>
          </div>
          <div className="diagram-legend">
            {[['L5–7 Application data', 'var(--purple)'], ['L4 Transport', 'var(--blue)'], ['L3 Network', 'var(--green)'], ['L2 Link', 'var(--amber)']].map(([label, color]) => (
              <span key={label}><i style={{ background: color }}></i>{label}</span>
            ))}
            <span className="diagram-note">Not to scale · ping skips L4: IPv4 carries ICMP directly</span>
          </div>
        </div>
        <LayerInspector layer={layer} view={view} />
      </section>
    </>
  );
}
