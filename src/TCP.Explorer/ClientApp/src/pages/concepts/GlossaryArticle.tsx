import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router';
import { glossary, glossaryById } from '../../content/glossary';
import { layers, type LayerSlug } from '../../content/layers';
import { LayerTag } from '../../components/LayerTag';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';

type LayerFilter = 'all' | LayerSlug | 'cross';

// Bottom of the stack first (L1 → L5–7), then ideas that span every layer. Only layers with terms get a button.
const filters: { id: LayerFilter; label: string; title: string }[] = [
  { id: 'all', label: 'All', title: 'All terms' },
  ...[...layers].reverse()
    .filter(layer => glossary.some(entry => entry.layers.includes(layer.slug)))
    .map(layer => ({ id: layer.slug, label: layer.number, title: `${layer.number} · ${layer.name}` })),
  { id: 'cross', label: 'Cross-layer', title: 'Ideas that apply at every layer' }
];
const sorted = [...glossary].sort((a, b) => a.term.localeCompare(b.term, 'en', { sensitivity: 'base' }));

export function GlossaryArticle() {
  useDocumentTitle('Glossary');
  const { hash } = useLocation();
  const target = decodeURIComponent(hash.slice(1));
  const [query, setQuery] = useState('');
  const [layer, setLayer] = useState<LayerFilter>('all');

  const entries = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return sorted.filter(entry =>
      (layer === 'all' || (layer === 'cross' ? entry.layers.length === 0 : entry.layers.includes(layer))) &&
      (!needle || [entry.term, entry.expansion ?? '', entry.definition, ...(entry.matches ?? [])].some(text => text.toLowerCase().includes(needle))));
  }, [query, layer]);

  // Deep links such as /concepts/glossary#fcs land on (and highlight) the entry, even if a filter was hiding it.
  useEffect(() => {
    if (!glossaryById.has(target)) return;
    setQuery('');
    setLayer('all');
    requestAnimationFrame(() => document.getElementById(target)?.scrollIntoView({ block: 'start' }));
  }, [target]);

  return (
    <>
      <PageHeading eyebrow="Reference" title="Glossary" next={{ to: '/concepts/pdus', label: 'One payload, five names' }}>
        <p>Every abbreviation and term the Explorer uses, tagged by layer (L1 physical up to L5–7 application), with what TCP.Core does about it. Dotted-underlined words elsewhere in the app link here.</p>
      </PageHeading>
      <div className="glossary-tools">
        <input
          type="search" className="glossary-search" placeholder="Filter terms… e.g. FCS, window, fragment"
          aria-label="Filter glossary" value={query} onChange={event => setQuery(event.target.value)}
        />
        <div className="segmented" role="group" aria-label="Layer">
          {filters.map(filter => (
            <button key={filter.id} type="button" title={filter.title} aria-label={filter.title} aria-pressed={layer === filter.id} onClick={() => setLayer(filter.id)}>{filter.label}</button>
          ))}
        </div>
      </div>
      <p className="small-muted glossary-count" aria-live="polite">{entries.length} of {glossary.length} terms</p>
      <dl className="glossary">
        {entries.map(entry => (
          <div key={entry.id} id={entry.id} className={`glossary-entry${entry.id === target ? ' targeted' : ''}`}>
            <dt>
              <a href={`#${entry.id}`} className="glossary-term">{entry.term}</a>
              {entry.expansion && <span className="glossary-expansion">{entry.expansion}</span>}
              <span className="glossary-layers">
                {entry.layers.length ? entry.layers.map(slug => <LayerTag key={slug} layer={slug} />) : <span className="layer-tag cross-layer">All layers</span>}
              </span>
            </dt>
            <dd>
              <p>{entry.definition}</p>
              {entry.inCode && <p className="glossary-code"><span>In TCP.Core</span>{entry.inCode}</p>}
              {(entry.related?.length || entry.see) && (
                <div className="glossary-links">
                  {entry.related?.map(id => <Link key={id} to={`/concepts/glossary#${id}`} preventScrollReset>{glossaryById.get(id)!.term}</Link>)}
                  {entry.see && <Link className="glossary-see" to={entry.see.to}>{entry.see.label} →</Link>}
                </div>
              )}
            </dd>
          </div>
        ))}
      </dl>
      {entries.length === 0 && <p className="muted">No terms match. <button type="button" className="inline-link link-button" onClick={() => { setQuery(''); setLayer('all'); }}>Clear the filter</button></p>}
    </>
  );
}
