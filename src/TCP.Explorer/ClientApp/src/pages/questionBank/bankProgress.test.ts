import { questionBank, assembleQuestion } from '../../content/questionBank';
import { fundamentals } from '../../content/questionBank/fundamentals';
import { bankProgressKey, legacyBankProgressKey, getBankProgressNotice, loadBankProgress } from './bankProgress';

beforeEach(() => localStorage.clear());
const q = questionBank[0]!;
const stored = () => ({ revision: q.revision, selected: q.choiceIds[q.answer], checked: true, firstCorrect: true, review: true });

test('saved answers retain meaning after display choices and source questions are reordered', () => {
  localStorage.setItem(bankProgressKey, JSON.stringify({ [q.id]: stored() }));
  const reordered = { ...q, choices: q.choices.slice().reverse(), choiceIds: q.choiceIds.slice().reverse(), answer: 3 - q.answer };
  const progress = loadBankProgress([questionBank[1]!, reordered]);
  expect(progress[q.id]?.selected).toBe(reordered.choiceIds[reordered.answer]);
  expect(progress[q.id]?.firstCorrect).toBe(true);
  expect(progress[q.id]?.checked).toBe(true);
});

test('a content revision retires scores while preserving the review flag', () => {
  localStorage.setItem(bankProgressKey, JSON.stringify({ [q.id]: stored() }));
  const changed = assembleQuestion({ ...fundamentals[0]!, prompt: 'Revised topology question' }, 'fundamentals');
  const progress = loadBankProgress([changed]);
  expect(progress[q.id]).toEqual({ revision: changed.revision, checked: false, review: true });
});

test('legacy numeric responses are not reinterpreted and the legacy snapshot remains untouched', () => {
  const legacy = JSON.stringify({
    [q.id]: { selected: 0, checked: true, firstCorrect: true, review: true },
    'fundamentals-007': { selected: 0, checked: true, firstCorrect: true, review: true }
  });
  localStorage.setItem(legacyBankProgressKey, legacy);
  expect(getBankProgressNotice()).toContain('Earlier answers were not carried over');
  expect(loadBankProgress()[q.id]).toEqual({ revision: q.revision, checked: false, review: true });
  expect(loadBankProgress()['fundamentals-007']).toBeUndefined();
  expect(loadBankProgress()['fundamentals-ethernet-medium']).toBeUndefined();
  expect(localStorage.getItem(legacyBankProgressKey)).toBe(legacy);
});

test('invalid choice identities, obsolete revisions, and malformed storage cannot restore scores', () => {
  localStorage.setItem(bankProgressKey, JSON.stringify({ [q.id]: { ...stored(), selected: 'unknown choice' } }));
  expect(loadBankProgress()[q.id]?.firstCorrect).toBeUndefined();
  expect(loadBankProgress()[q.id]?.checked).toBe(false);
  localStorage.setItem(bankProgressKey, JSON.stringify({ [q.id]: { ...stored(), revision: 'obsolete' } }));
  expect(getBankProgressNotice()).toContain('earlier results were cleared');
  expect(loadBankProgress()[q.id]?.firstCorrect).toBeUndefined();
  localStorage.setItem(bankProgressKey, '{invalid JSON');
  expect(loadBankProgress()).toEqual({});
});
