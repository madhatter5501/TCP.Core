import type { CSSProperties } from 'react';
import { layers, type LayerSlug } from '../content/layers';

/** A layer label in the app's L-number style, e.g. “L2 · Link”, in that layer's color. */
export function LayerTag({ layer, name = true }: { layer: LayerSlug; name?: boolean }) {
  const found = layers.find(candidate => candidate.slug === layer)!;
  return (
    <span className="layer-tag" style={{ '--layer-color': found.color } as CSSProperties}>
      {found.number}{name && <>{' '}<span className="layer-tag-name">· {found.name}</span></>}
    </span>
  );
}
