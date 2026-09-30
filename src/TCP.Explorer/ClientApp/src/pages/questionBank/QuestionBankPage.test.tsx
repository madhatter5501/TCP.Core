import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '../../test/renderRoute';
import { questionBank } from '../../content/questionBank';
import { bankProgressKey } from './bankProgress';

beforeEach(() => localStorage.clear());

async function openBank(path = '/practice/bank') {
  const result = renderRoute(path);
  await screen.findByRole('heading', { name: '200-question bank' });
  return result;
}

test('the bank exposes 200 questions and filters sections, search, and question styles', async () => {
  await openBank();
  expect(screen.getByText('200 questions in this queue')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Check answer' })).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText('Section'), 'services');
  expect(screen.getByText('20 questions in this queue')).toBeInTheDocument();
  expect(within(screen.getByLabelText('Question in queue')).getAllByRole('option')).toHaveLength(20);
  const search = screen.getByLabelText('Search questions or topic codes');
  await userEvent.type(search, 'NTP');
  expect(search).toHaveValue('NTP');
  expect(search).toHaveFocus();
  expect(screen.getByText('2 questions in this queue')).toBeInTheDocument();
  await userEvent.clear(search);
  await userEvent.selectOptions(screen.getByLabelText('Question style'), 'Troubleshoot');
  expect(screen.getByText('4 questions in this queue')).toBeInTheDocument();
});

test('first-check results survive retries and reload, with review flags and answer feedback', async () => {
  const first = await openBank();
  const q = questionBank[0]!;
  await userEvent.click(screen.getByRole('radio', { name: q.choices[(q.answer + 1) % 4]! }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  expect(screen.getByRole('status', { name: 'Answer feedback' })).toHaveTextContent('Not quite');
  expect(screen.getByText('0 / 1 correct on first check')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('radio', { name: q.choices[q.answer]! }));
  expect(screen.queryByRole('status', { name: 'Answer feedback' })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  expect(screen.getByText('1 currently correct')).toBeInTheDocument();
  expect(screen.getByText('0 / 1 correct on first check')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Save for review' }));
  expect(screen.getByRole('status', { name: 'Queue feedback' })).toHaveTextContent('Saved to your review list');
  first.unmount();
  await openBank();
  expect(screen.getByRole('button', { name: 'Saved for review ✓' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByRole('status', { name: 'Answer feedback' })).toHaveTextContent(q.explanation);
  expect(screen.getByText('0 / 1 correct on first check')).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Practice queue'), 'review');
  expect(screen.getByText('1 questions in this queue')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Saved for review ✓' }));
  await userEvent.click(screen.getByRole('button', { name: 'Refresh queue' }));
  expect(screen.getByRole('heading', { name: 'No questions match these filters' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Show all 200 questions' }));
  expect(screen.getByText('200 questions in this queue')).toBeInTheDocument();
});

test('an unanswered queue keeps checked feedback visible and navigation skips checked questions', async () => {
  const { router } = await openBank();
  await userEvent.selectOptions(screen.getByLabelText('Practice queue'), 'unanswered');
  const q = questionBank[0]!;
  await userEvent.click(screen.getByRole('radio', { name: q.choices[q.answer]! }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  expect(screen.getByRole('status', { name: 'Answer feedback' })).toHaveTextContent('Correct');
  expect(screen.getByText('200 questions in this queue')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next unanswered' }));
  expect(router.state.location.search).toBe('?q=fundamentals-002');
  await userEvent.click(screen.getByRole('button', { name: 'Refresh queue' }));
  expect(screen.getByText('199 questions in this queue')).toBeInTheDocument();
});

test('incorrect answers are reviewable and shuffle preserves the filtered question set', async () => {
  await openBank('/practice/bank?q=connectivity-001');
  const q = questionBank.find(q => q.id === 'connectivity-001')!;
  await userEvent.click(screen.getByRole('radio', { name: q.choices[(q.answer + 1) % 4]! }));
  await userEvent.click(screen.getByRole('button', { name: 'Check answer' }));
  await userEvent.selectOptions(screen.getByLabelText('Practice queue'), 'incorrect');
  expect(screen.getByText('1 questions in this queue')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: q.prompt })).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Practice queue'), 'all');
  await userEvent.selectOptions(screen.getByLabelText('Section'), 'automation');
  await userEvent.click(screen.getByRole('button', { name: 'Shuffle queue' }));
  const ids = within(screen.getByLabelText('Question in queue')).getAllByRole('option').map(option => (option as HTMLOptionElement).value);
  expect(new Set(ids)).toEqual(new Set(questionBank.filter(q => q.section === 'automation').map(q => q.id)));
  expect(screen.getByRole('status', { name: 'Queue feedback' })).toHaveTextContent('shuffled');
});

test('invalid saved selections cannot break the bank and failed storage is reported', async () => {
  localStorage.setItem(bankProgressKey, JSON.stringify({ 'fundamentals-001': { selected: 99, checked: true, review: true } }));
  const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('unavailable'); });
  try {
    await openBank();
    expect(screen.getByRole('button', { name: 'Check answer' })).toBeDisabled();
    expect(screen.getByText(/Browser storage is unavailable/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Saved for review ✓' })).toHaveAttribute('aria-pressed', 'true');
  } finally { setItem.mockRestore(); }
});
