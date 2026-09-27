import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '../test/renderRoute';

test('home offers each section by intent', () => {
  renderRoute('/');
  expect(screen.getByRole('heading', { level: 1, name: 'What’s inside a packet?' })).toBeInTheDocument();
  for (const title of ['Walk the layers', 'Transmit real packets', 'Size things up', 'Keep the names straight']) {
    expect(screen.getByRole('heading', { name: title })).toBeInTheDocument();
  }
});

test('the primary navigation marks the current section', () => {
  renderRoute('/sizes');
  expect(screen.getByRole('link', { name: 'MTU & MSS' })).toHaveAttribute('aria-current', 'page');
  expect(screen.getByRole('link', { name: 'Layers' })).not.toHaveAttribute('aria-current');
});

test('/layers redirects to the network layer', () => {
  const { router } = renderRoute('/layers');
  expect(router.state.location.pathname).toBe('/layers/network');
  expect(screen.getByRole('heading', { level: 2, name: 'Network' })).toBeInTheDocument();
});

test('a layer and detail view can be deep linked', () => {
  renderRoute('/layers/link/gotchas');
  expect(screen.getByRole('heading', { level: 2, name: 'Link' })).toBeInTheDocument();
  expect(screen.getByRole('tab', { name: 'Gotchas' })).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByText('ARP is not inside an IP packet')).toBeInTheDocument();
});

test('arrow keys move between detail tabs and update the URL', async () => {
  const { router } = renderRoute('/layers/transport');
  await userEvent.click(screen.getByRole('tab', { name: 'Overview' }));
  await userEvent.keyboard('{ArrowRight}');
  expect(router.state.location.pathname).toBe('/layers/transport/headers');
  expect(screen.getByRole('tab', { name: 'PDU & bits' })).toHaveFocus();
});

test('header variants switch the field table', async () => {
  renderRoute('/layers/transport/headers');
  expect(screen.getByText('Sequence number')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'UDP' }));
  expect(screen.getByText('One application datagram.')).toBeInTheDocument();
  expect(screen.queryByText('Sequence number')).not.toBeInTheDocument();
});

test('stepping walks to the next layer in the chosen direction', async () => {
  const { router } = renderRoute('/layers/application');
  await userEvent.click(screen.getByRole('button', { name: 'Next layer' }));
  expect(router.state.location.pathname).toBe('/layers/transport');
  await userEvent.click(screen.getByRole('button', { name: '↑ Receive' }));
  expect(router.state.location.pathname).toBe('/layers/physical');
});

test('unknown layers and views are not found', () => {
  renderRoute('/layers/session');
  expect(screen.getByRole('heading', { name: 'Nothing at this address.' })).toBeInTheDocument();
});

test('a transmit link preselects its experiment and defaults', () => {
  renderRoute('/transmit?scenario=loss');
  expect(screen.getByLabelText('Experiment')).toHaveValue('loss');
  expect(screen.getByLabelText('Bytes the app writes')).toHaveValue(4000);
  expect(screen.getByText(/Reassembly can never complete/)).toBeInTheDocument();
});

test('choosing an experiment updates the URL and resets its defaults', async () => {
  const { router } = renderRoute('/transmit');
  await userEvent.selectOptions(screen.getByLabelText('Experiment'), 'ping');
  expect(router.state.location.search).toBe('?scenario=ping');
  expect(screen.getByLabelText('Bytes the app writes')).toHaveValue(32);
});

test('the size lab recalculates and reports invalid input', async () => {
  renderRoute('/sizes');
  expect(screen.getByText('3 TCP segments for 4,000 B')).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('TCP options'), '12');
  expect(screen.getByText('3 TCP segments for 4,000 B')).toBeInTheDocument();
  expect(screen.getByText(/= 1,448 B/)).toBeInTheDocument();
  const mtu = screen.getByLabelText(/Outgoing link MTU/);
  await userEvent.clear(mtu);
  expect(screen.getByRole('alert')).toHaveTextContent('Link MTU must be a whole number from 68 to 9000.');
});

test('DF blocks the oversized datagram in the fragment experiment', async () => {
  renderRoute('/sizes');
  expect(screen.getByText('Fragment 3')).toBeInTheDocument();
  await userEvent.click(screen.getByLabelText('Set Don’t Fragment (DF)'));
  expect(screen.getByText(/prevents fragmentation/)).toHaveTextContent('DF prevents fragmentation');
});

test('concepts default to the first article and link between articles', async () => {
  const { router } = renderRoute('/concepts');
  expect(router.state.location.pathname).toBe('/concepts/pdus');
  await userEvent.click(screen.getByRole('link', { name: 'Read what that means' }));
  expect(router.state.location.pathname).toBe('/concepts/datagram');
  expect(screen.getByRole('heading', { level: 1, name: 'What is a datagram?' })).toBeInTheDocument();
});

test('unknown paths render the not-found page inside the layout', () => {
  renderRoute('/nope');
  expect(screen.getByRole('heading', { name: 'Nothing at this address.' })).toBeInTheDocument();
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
});
