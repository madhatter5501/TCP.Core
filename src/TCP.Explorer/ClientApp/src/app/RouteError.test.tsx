import { screen } from '@testing-library/react';
import { renderRoute } from '../test/renderRoute';

vi.mock('../pages/sizes/SizesPage', () => ({
  SizesPage: () => { throw new Error('Size lab exploded.'); }
}));

test('a page that throws renders the error inside the layout', () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  renderRoute('/sizes');
  expect(screen.getByRole('heading', { name: 'This page failed to render.' })).toBeInTheDocument();
  expect(screen.getByText(/Size lab exploded\./)).toBeInTheDocument();
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
});
