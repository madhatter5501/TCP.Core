import { useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router';
import { glossaryById } from '../content/glossary';
import './term.css';

const tooltipWidth = 300;
const edge = 12;

/**
 * A glossary term in running text: a link to its entry, with the definition shown on hover or focus.
 * The tooltip is portalled with fixed positioning so scrolling panes and overflow never clip it.
 */
export function Term({ id, children }: { id: string; children?: ReactNode }) {
  const entry = glossaryById.get(id);
  const tooltipId = useId();
  const anchor = useRef<HTMLAnchorElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<{ left: number; top: number; above: boolean } | null>(null);

  useLayoutEffect(() => {
    if (!open || !anchor.current) { setPosition(null); return; }
    const rect = anchor.current.getBoundingClientRect();
    const left = Math.min(Math.max(edge, rect.left + rect.width / 2 - tooltipWidth / 2), window.innerWidth - tooltipWidth - edge);
    const above = rect.bottom + 180 > window.innerHeight && rect.top > 200;
    setPosition({ left, top: above ? rect.top - 8 : rect.bottom + 8, above });
  }, [open]);

  if (!entry) return <>{children}</>;
  const close = () => setOpen(false);
  return (
    <>
      <Link
        ref={anchor}
        className="term"
        to={`/concepts/glossary#${entry.id}`}
        aria-describedby={open ? tooltipId : undefined}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={close}
        onFocus={() => setOpen(true)}
        onBlur={close}
        onClick={close}
        onKeyDown={event => { if (event.key === 'Escape') close(); }}
      >
        {children ?? entry.term}
      </Link>
      {open && position && createPortal(
        <div
          id={tooltipId}
          role="tooltip"
          className={`term-tooltip${position.above ? ' above' : ''}`}
          style={{ left: position.left, top: position.top, width: tooltipWidth }}
        >
          <strong>{entry.term}</strong>{entry.expansion && <span className="term-expansion"> · {entry.expansion}</span>}
          <p>{entry.definition}</p>
          <span className="term-more">Click for the glossary entry</span>
        </div>,
        document.body
      )}
    </>
  );
}
