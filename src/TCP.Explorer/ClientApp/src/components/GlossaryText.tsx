import type { ReactNode } from 'react';
import { glossary } from '../content/glossary';
import { Term } from './Term';

const termBySpelling = new Map(glossary.flatMap(entry => (entry.matches ?? []).map(spelling => [spelling, entry.id] as const)));

// Longest spellings first so "path MTU" wins over "MTU". Whole words only, case-sensitive.
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pattern = new RegExp(
  `(?<![\\w-])(${[...termBySpelling.keys()].sort((a, b) => b.length - a.length).map(escape).join('|')})(?![\\w])`,
  'g'
);

/**
 * Renders prose with the first mention of each glossary term linked to its definition.
 * Later mentions stay plain so a paragraph never turns into a wall of links.
 */
export function GlossaryText({ children }: { children: string }) {
  const parts: ReactNode[] = [];
  const linked = new Set<string>();
  let last = 0;
  for (const match of children.matchAll(pattern)) {
    const id = termBySpelling.get(match[0])!;
    if (linked.has(id)) continue;
    linked.add(id);
    parts.push(children.slice(last, match.index), <Term key={match.index} id={id}>{match[0]}</Term>);
    last = match.index + match[0].length;
  }
  parts.push(children.slice(last));
  return <>{parts}</>;
}
