import { useEffect, useRef, type KeyboardEvent } from 'react';
import { LayerTag } from '../../components/LayerTag';
import { protocolLayer } from './protocolLayer';
import type { CapturedFrame } from './types';

interface FrameLadderProps {
  frames: CapturedFrame[];
  activeFrame: number;
  onSelect: (index: number) => void;
}

/**
 * Sequence ("ladder") diagram of the captured frames: Host A on the left, Host B on the right,
 * one selectable row per frame. Arrow keys move the selection.
 */
export function FrameLadder({ frames, activeFrame, onSelect }: FrameLadderProps) {
  const rows = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => { rows.current[activeFrame]?.scrollIntoView({ block: 'nearest' }); }, [activeFrame]);

  const onKeyDown = (event: KeyboardEvent) => {
    const next = { ArrowDown: activeFrame + 1, ArrowUp: activeFrame - 1, Home: 0, End: frames.length - 1 }[event.key];
    if (next === undefined || next < 0 || next >= frames.length) return;
    event.preventDefault();
    onSelect(next);
    rows.current[next]?.focus();
  };

  return (
    <ol className="ladder" aria-label="Captured frames" onKeyDown={onKeyDown}>
      {frames.map((frame, index) => {
        const fromA = frame.from === 'Host A';
        return (
          <li key={frame.number}>
            <button
              ref={element => { rows.current[index] = element; }}
              type="button"
              className={`ladder-row ${fromA ? 'from-a' : 'from-b'} ${frame.delivery.toLowerCase()}`}
              aria-pressed={index === activeFrame}
              aria-label={`#${frame.number} ${frame.protocol}, ${frame.from} to ${frame.to}, ${frame.length} bytes, ${frame.delivery.toLowerCase()}`}
              tabIndex={index === activeFrame ? 0 : -1}
              onClick={() => onSelect(index)}
            >
              <span className="ladder-time">{(frame.timeMs / 1000).toFixed(3)}s</span>
              <span className="ladder-track">
                <span className="ladder-label">#{frame.number} {frame.protocol}</span>
                <span className="ladder-arrow" aria-hidden="true"></span>
              </span>
              <span className="ladder-meta"><LayerTag layer={protocolLayer(frame.protocol)} name={false} /> {frame.length} B{frame.delivery !== 'Delivered' && <span className="ladder-delivery"> · {frame.delivery}</span>}</span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
