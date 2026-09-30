import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '../../test/renderRoute';
import { progressKey } from './practiceProgress';

beforeEach(() => localStorage.clear());

const chooseSubnet = async () => {
  await userEvent.click(screen.getByRole('radio', { name: 'Network .64; broadcast .95; hosts .65–.94' }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer 1' }));
};

test('questions explain decisions, clear stale feedback, and retain work when switching topics', async () => {
  renderRoute('/practice');
  expect(screen.getByRole('link', { name: 'CCNA Practice' })).toHaveAttribute('aria-current', 'page');
  const check = screen.getByRole('button', { name: 'Check answer 1' });
  expect(check).toBeDisabled();
  await userEvent.click(screen.getByRole('radio', { name: 'Network .0; broadcast .255; hosts .1–.254' }));
  await userEvent.click(check);
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('Not quite');
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('30 usable hosts');
  await userEvent.click(screen.getByRole('radio', { name: 'Network .64; broadcast .95; hosts .65–.94' }));
  expect(screen.queryByRole('status', { name: 'Answer 1 feedback' })).not.toBeInTheDocument();
  await userEvent.click(check);
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('Work through the decision');
  expect(screen.getByText('1 / 36 questions correct')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: /Read a forwarding decision/ }));
  expect(screen.getByRole('button', { name: 'Check answer 1' })).toBeDisabled();
  await userEvent.click(screen.getByRole('radio', { name: '192.0.2.2, using the /16 route' }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer 1' }));
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('longest matching prefix');
  await userEvent.click(screen.getByRole('button', { name: /Find the subnet boundary/ }));
  expect(screen.getByRole('radio', { name: 'Network .64; broadcast .95; hosts .65–.94' })).toBeChecked();
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('Correct');
});

test('ratings give feedback, persist with answers and notes, and restore after remount', async () => {
  const first = renderRoute('/practice');
  await chooseSubnet();
  await userEvent.type(screen.getByLabelText('Your reasoning and questions to revisit'), 'A /27 contains 32 addresses.');
  await userEvent.click(screen.getByRole('button', { name: 'I can explain this' }));
  expect(screen.getByRole('status', { name: 'Rating feedback' })).toHaveTextContent('Marked “Can explain”');
  expect(screen.getByRole('button', { name: 'I can explain this' })).toHaveAttribute('aria-pressed', 'true');
  expect(JSON.parse(localStorage.getItem(progressKey)! ).subnet.confidence).toBe('ready');
  first.unmount();
  renderRoute('/practice');
  expect(screen.getByText('1 / 12 self-rated confident')).toBeInTheDocument();
  expect(screen.getByText('1 / 36 questions correct')).toBeInTheDocument();
  expect(screen.getByLabelText('Your reasoning and questions to revisit')).toHaveValue('A /27 contains 32 addresses.');
  expect(screen.getByRole('button', { name: 'I can explain this' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByRole('status', { name: 'Answer 1 feedback' })).toHaveTextContent('Correct');
  await userEvent.click(screen.getByRole('button', { name: 'Clear rating' }));
  expect(screen.getByText('0 / 12 self-rated confident')).toBeInTheDocument();
  expect(screen.getByText('1 / 36 questions correct')).toBeInTheDocument();
  expect(screen.getByRole('status', { name: 'Rating feedback' })).toHaveTextContent('Rating cleared');
});

test('review filter reacts when the last review topic is marked confident', async () => {
  renderRoute('/practice');
  await userEvent.click(screen.getByRole('button', { name: 'Needs review' }));
  expect(screen.getByText('1 need review · 11 unrated')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('checkbox', { name: 'Show only topics needing review' }));
  expect(screen.queryByRole('button', { name: /Read a forwarding decision/ })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'I can explain this' }));
  expect(screen.getByText('1 / 12 self-rated confident')).toBeInTheDocument();
  expect(screen.getByText(/Your review list is clear/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Show all topics' }));
  expect(screen.getByRole('button', { name: /Find the subnet boundary.*Can explain/ })).toBeInTheDocument();
});

test('harder checkpoints are independently graded and next topic supports deep links', async () => {
  const { router } = renderRoute('/practice?topic=subnet');
  await userEvent.click(screen.getByRole('radio', { name: 'Network .128, broadcast .143, hosts .129–.142' }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer 2' }));
  expect(screen.getByRole('status', { name: 'Answer 2 feedback' })).toHaveTextContent('last usable host');
  await userEvent.click(screen.getByRole('radio', { name: '.0/26, .64/27, .96/28' }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer 3' }));
  expect(screen.getByRole('status', { name: 'Answer 3 feedback' })).toHaveTextContent('50 hosts need /26');
  expect(screen.getByText('2 / 36 questions correct')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next topic →' }));
  expect(router.state.location.search).toBe('?topic=gateway');
  expect(screen.getByRole('heading', { name: 'Choose the next-hop MAC' })).toHaveFocus();
  await userEvent.selectOptions(screen.getByLabelText('Choose a topic'), 'ospf');
  expect(router.state.location.search).toBe('?topic=ospf');
  expect(screen.getByRole('heading', { name: 'Find an OSPF mismatch' })).toHaveFocus();
});

test('bad saved data and storage write failure do not break the exercises', async () => {
  localStorage.setItem(progressKey, '{broken');
  const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('unavailable'); });
  try {
    renderRoute('/practice?topic=api');
    expect(screen.getByText(/Browser storage is unavailable; progress/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'I can explain this' }));
    expect(screen.getByRole('button', { name: 'I can explain this' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('heading', { name: 'Hands-on lab task' })).toBeInTheDocument();
  } finally { setItem.mockRestore(); }
});
