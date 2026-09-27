import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { glossary } from '../../content/glossary';
import { renderRoute } from '../../test/renderRoute';

test('lists every term and filters by text and category', async () => {
  renderRoute('/concepts/glossary');
  expect(screen.getByText(`${glossary.length} of ${glossary.length} terms`)).toBeInTheDocument();
  await userEvent.type(screen.getByRole('searchbox', { name: 'Filter glossary' }), 'frame check');
  expect(screen.getByText(`1 of ${glossary.length} terms`)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'FCS' })).toBeInTheDocument();
  await userEvent.clear(screen.getByRole('searchbox'));
  await userEvent.click(screen.getByRole('button', { name: 'L2 · Link' }));
  const terms = screen.getAllByRole('term').map(term => within(term).getByRole('link').textContent);
  expect(terms).toContain('ARP');
  expect(terms).not.toContain('MSS');
});

test('a deep link highlights its entry and related terms link to each other', async () => {
  const { router } = renderRoute('/concepts/glossary#fcs');
  expect(document.getElementById('fcs')).toHaveClass('targeted');
  await userEvent.click(within(document.getElementById('fcs')!).getByRole('link', { name: 'CRC' }));
  expect(router.state.location.hash).toBe('#crc');
  expect(document.getElementById('crc')).toHaveClass('targeted');
});

test('terms in other pages lead to the glossary', async () => {
  const { router } = renderRoute('/layers/link/gotchas');
  await userEvent.click(screen.getAllByRole('link', { name: 'FCS' })[0]!);
  expect(router.state.location.pathname + router.state.location.hash).toBe('/concepts/glossary#fcs');
});

test('entries are tagged with every layer they belong to', async () => {
  renderRoute('/concepts/glossary');
  const tags = (id: string) => [...document.getElementById(id)!.querySelectorAll('.layer-tag')].map(tag => tag.textContent);
  expect(tags('fcs')).toEqual(['L2 · Link']);
  expect(tags('checksum')).toEqual(['L3 · Network', 'L4 · Transport']);
  expect(tags('preamble')).toEqual(['L1 · Physical']);
  expect(tags('message-framing')).toEqual(['L5–7 · Application']);
  expect(tags('octet')).toEqual(['All layers']);
  await userEvent.click(screen.getByRole('button', { name: 'L3 · Network' }));
  const terms = screen.getAllByRole('term').map(term => within(term).getByRole('link').textContent);
  expect(terms).toEqual(expect.arrayContaining(['Checksum', 'DF', 'MTU']));
  expect(terms).not.toContain('FCS');
});
