import { useCallback, useRef } from 'react';
import { layers } from '../../content/layers';
import { useCanvas, type CanvasSize } from '../../components/useCanvas';

export type Direction = 'send' | 'receive';

interface StackCanvasProps {
  selected: number;
  direction: Direction;
  onSelect: (index: number) => void;
}

const mono = 'ui-monospace, SFMono-Regular, Consolas, monospace';
const signalBits = '10110010011101011000101101010110110010';

/** Conceptual encapsulation diagram. Blocks show nesting, deliberately not byte proportions. */
export function StackCanvas({ selected, direction, onSelect }: StackCanvasProps) {
  const hitAreas = useRef<{ top: number; bottom: number; index: number }[]>([]);

  const draw = useCallback((ctx: CanvasRenderingContext2D, { width, height }: CanvasSize) => {
    const narrow = width < 430;
    const labelWidth = narrow ? 106 : 137;
    const startX = labelWidth + 9;
    const endX = width - 13;
    const rowHeight = (height - 30) / layers.length;
    const packetWidth = Math.max(100, endX - startX);
    const text = (value: string, x: number, y: number, color: string, size = 12, font = mono) => {
      ctx.fillStyle = color; ctx.font = `${size}px ${font}`; ctx.fillText(value, x, y);
    };
    const box = (x: number, y: number, w: number, h: number, fill: string, border?: string) => {
      ctx.beginPath(); ctx.roundRect(x, y, w, h, 5); ctx.fillStyle = fill; ctx.fill();
      if (border) { ctx.strokeStyle = border; ctx.lineWidth = 1; ctx.stroke(); }
    };
    const areas: typeof hitAreas.current = [];
    layers.forEach((layer, i) => {
      const y = 10 + i * rowHeight;
      const active = i === selected;
      if (active) box(0, y, width, rowHeight - 6, '#233244', '#3f536b');
      text(layer.number, 12, y + 22, layer.color, 12);
      text(layer.name, 12, y + 43, active ? '#f1f5fb' : '#b0bdce', narrow ? 13 : 14, 'system-ui, sans-serif');
      const barY = y + 14;
      if (i < 4) {
        const headerWidth = Math.max(27, Math.min(45, packetWidth * .145));
        const headers: [string, string][] = i === 0 ? [] : i === 1 ? [['TCP', '#6cafff']] : i === 2 ? [['IP', '#7ee7c5'], ['TCP', '#6cafff']] : [['ETH', '#f1be73'], ['IP', '#7ee7c5'], ['TCP', '#6cafff']];
        const inset = (3 - i) * (narrow ? 8 : 16);
        let x = startX + inset;
        const available = packetWidth - inset;
        for (const [name, color] of headers) {
          box(x, barY, headerWidth - 3, 31, color);
          text(name, x + 5, barY + 20, '#101a27', narrow ? 10 : 11);
          x += headerWidth;
        }
        const fcsWidth = i === 3 ? 27 : 0;
        const dataWidth = available - headers.length * headerWidth - fcsWidth;
        box(x, barY, dataWidth - 3, 31, '#a99bff');
        text(dataWidth > 120 ? 'APPLICATION DATA' : dataWidth > 65 ? 'DATA' : '…', x + 8, barY + 20, '#17162c', narrow ? 10 : 11);
        if (i === 3) { box(endX - 27, barY, 27, 31, '#223044', '#f1be73'); text('FCS', endX - 24, barY + 20, '#f1be73', 10); }
        text(direction === 'send' ? '↓' : '↑', startX + packetWidth / 2, y + rowHeight + 3, '#657d94', 14);
      } else {
        const baseY = y + 33;
        ctx.strokeStyle = active ? '#c4d9ed' : '#758ba3'; ctx.lineWidth = 1.5; ctx.beginPath();
        const step = packetWidth / signalBits.length;
        for (let b = 0; b < signalBits.length; b++) {
          const x = startX + b * step;
          const by = signalBits[b] === '1' ? baseY - 9 : baseY + 4;
          if (!b) ctx.moveTo(x, by); else ctx.lineTo(x, by);
          ctx.lineTo(x + step, by);
        }
        ctx.stroke();
        text('ENCODED SIGNALS · CONCEPTUAL', startX, y + 53, '#94a9c0', narrow ? 9 : 10);
      }
      areas.push({ top: y, bottom: y + rowHeight - 6, index: i });
    });
    hitAreas.current = areas;
  }, [selected, direction]);

  const canvasRef = useCanvas(draw);
  return (
    <canvas
      ref={canvasRef}
      className="clickable"
      aria-hidden="true"
      onClick={event => {
        const y = event.clientY - event.currentTarget.getBoundingClientRect().top;
        const area = hitAreas.current.find(candidate => y >= candidate.top && y <= candidate.bottom);
        if (area) onSelect(area.index);
      }}
    />
  );
}
