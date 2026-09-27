import { matchRoutes } from 'react-router';
import { routes } from '../app/routes';
import { glossary, glossaryById } from './glossary';

test('ids are unique and every related term exists', () => {
  expect(glossaryById.size).toBe(glossary.length);
  for (const entry of glossary) {
    for (const id of entry.related ?? []) expect(glossaryById.has(id), `${entry.id} → ${id}`).toBe(true);
    expect(entry.related ?? []).not.toContain(entry.id);
  }
});

test('no spelling is claimed by two entries', () => {
  const spellings = glossary.flatMap(entry => entry.matches ?? []);
  expect(new Set(spellings).size).toBe(spellings.length);
});

test('every “see” link resolves to a real page', () => {
  for (const entry of glossary.filter(candidate => candidate.see)) {
    const path = entry.see!.to.split('?')[0]!;
    const matches = matchRoutes(routes, path) ?? [];
    expect(matches.at(-1)?.route.path, `${entry.id} → ${path}`).not.toBe('*');
  }
});
