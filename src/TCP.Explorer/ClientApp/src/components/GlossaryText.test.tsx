import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { GlossaryText } from './GlossaryText';

const renderText = (text: string) => render(<MemoryRouter><p data-testid="text"><GlossaryText>{text}</GlossaryText></p></MemoryRouter>);

test('links the first mention of each term and keeps the text intact', () => {
  const text = 'The FCS follows the payload. A bad FCS drops the frame; the MTU excludes it.';
  renderText(text);
  expect(screen.getByTestId('text')).toHaveTextContent(text);
  const links = screen.getAllByRole('link');
  expect(links.map(link => link.textContent)).toEqual(['FCS', 'MTU']);
  expect(links[0]).toHaveAttribute('href', '/concepts/glossary#fcs');
});

test('prefers the longest spelling and matches whole, case-sensitive words only', () => {
  renderText('Path MTU discovery; FCSX and fcs and MTUs are different, DF-marked packets count.');
  const links = screen.getAllByRole('link');
  expect(links.map(link => [link.textContent, link.getAttribute('href')])).toEqual([
    ['Path MTU', '/concepts/glossary#path-mtu'],
    ['MTUs', '/concepts/glossary#mtu'],
    ['DF', '/concepts/glossary#df']
  ]);
});

test('hovering or focusing a term shows its definition', async () => {
  renderText('Watch the FCS.');
  const term = screen.getByRole('link', { name: 'FCS' });
  await userEvent.hover(term);
  expect(screen.getByRole('tooltip')).toHaveTextContent('Frame Check Sequence');
  expect(term).toHaveAccessibleDescription(/CRC-32/);
  await userEvent.unhover(term);
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  act(() => term.focus());
  expect(screen.getByRole('tooltip')).toBeInTheDocument();
  await userEvent.keyboard('{Escape}');
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
});
