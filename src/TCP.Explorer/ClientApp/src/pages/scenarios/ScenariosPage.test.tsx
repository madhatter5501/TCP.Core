import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '../../test/renderRoute';
import { ccnaScenarios } from '../../content/ccnaScenarios';

const pageTitle = () => screen.findByRole('heading', { level: 1, name: 'Topology scenarios' });

test('deep links show the intended case, provenance, and a diagram of both paths', async () => {
  renderRoute('/practice/scenarios?scenario=routes');
  await pageTitle();
  expect(screen.getByLabelText('Choose a scenario')).toHaveValue('routes');
  expect(screen.getByRole('img', { name: /R1 has separate paths through R2 and R3/ })).toBeInTheDocument();
  expect(screen.getByText(/Original topology diagrams and authored configuration examples/)).toBeInTheDocument();
  expect(screen.queryByText(/View Packet Tracer evidence/)).not.toBeInTheDocument();
  expect(screen.queryByRole('status', { name: 'Scenario feedback' })).not.toBeInTheDocument();
});

test('retries keep first results and stages retain their own selections', async () => {
  renderRoute('/practice/scenarios?scenario=vlan');
  await pageTitle();
  expect(screen.getByRole('button', { name: 'Check answer' })).toBeDisabled();
  const question = ccnaScenarios[0]!.questions[0]!;
  await userEvent.click(screen.getByRole('radio', { name: question.distractors[0] }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  expect(screen.getByRole('status', { name: 'Scenario feedback' })).toHaveTextContent('Not quite');
  await userEvent.click(screen.getByRole('radio', { name: question.correct }));
  expect(screen.queryByRole('status', { name: 'Scenario feedback' })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  expect(screen.getByRole('status', { name: 'Scenario feedback' })).toHaveTextContent('Correct');
  expect(screen.getByText(/0 \/ 1 correct on first check/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next stage' }));
  expect(screen.getByRole('region', { name: 'Diagnose question' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Check answer' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Previous stage' }));
  expect(screen.getByRole('radio', { name: question.correct })).toBeChecked();
});

test('scenario selection updates the URL and downloads matching lab instructions', async () => {
  const { router } = renderRoute('/practice/scenarios');
  await pageTitle();
  await userEvent.selectOptions(screen.getByLabelText('Choose a scenario'), 'pat');
  expect(router.state.location.search).toBe('?scenario=pat');
  await userEvent.click(screen.getByText('Build, break, and repair this lab — includes solutions'));
  const link = screen.getByRole('link', { name: 'Download lab instructions' });
  expect(link).toHaveAttribute('download', 'pat-lab.txt');
  const body = decodeURIComponent(link.getAttribute('href')!.split(',').slice(1).join(','));
  expect(body).toContain('question evidence are illustrative');
  expect(body).toContain('ip nat outside');
  expect(body).not.toMatch(/Packet Tracer|\.pkt/);
  await userEvent.click(screen.getByText('View Packet Tracer captures'));
  expect(screen.getByRole('link', { name: 'Download fault lab (.pkt)' })).toHaveAttribute('href', '/labs/ccna/pat/fault.pkt');
  await userEvent.click(screen.getByRole('button', { name: '3. Verify' }));
  expect(within(screen.getByRole('region', { name: 'Verify question' })).getAllByRole('radio')).toHaveLength(4);
});

test('an unknown scenario falls back to the first case', async () => {
  renderRoute('/practice/scenarios?scenario=missing');
  await pageTitle();
  expect(screen.getByLabelText('Choose a scenario')).toHaveValue('vlan');
});
