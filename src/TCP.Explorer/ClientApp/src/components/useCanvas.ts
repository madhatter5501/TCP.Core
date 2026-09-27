import { useEffect, useRef } from 'react';

export interface CanvasSize { width: number; height: number }

/**
 * Keeps a canvas's backing store matched to its CSS size and device pixel ratio, and redraws
 * whenever the size or `draw` changes. `draw` receives a context already scaled to CSS pixels.
 */
export function useCanvas(draw: (context: CanvasRenderingContext2D, size: CanvasSize) => void) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const drawRef = useRef(draw);
  drawRef.current = draw;

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d');
    if (!canvas || !context) return;
    const render = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const ratio = window.devicePixelRatio || 1;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.clearRect(0, 0, width, height);
      drawRef.current(context, { width, height });
    };
    render();
    const observer = new ResizeObserver(render);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [draw]);

  return canvasRef;
}
