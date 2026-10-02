import { questionBank } from '../../content/questionBank';
import type { BankQuestion } from '../../content/questionBank/types';

export interface BankAttempt {
  revision: string;
  selected?: string;
  checked: boolean;
  review: boolean;
  firstCorrect?: boolean;
}
export type BankProgress = Record<string, BankAttempt>;
export const bankProgressKey = 'tcp-explorer.ccna-bank.v2';
export const legacyBankProgressKey = 'tcp-explorer.ccna-bank.v1';
export const emptyAttempt = (question?: BankQuestion): BankAttempt => ({ revision: question?.revision ?? '', checked: false, review: false });

export function loadBankProgress(questions: readonly BankQuestion[] = questionBank): BankProgress {
  try {
    const saved = localStorage.getItem(bankProgressKey);
    const legacy = saved === null;
    const data: unknown = JSON.parse(saved ?? localStorage.getItem(legacyBankProgressKey) ?? '{}');
    if (!data || typeof data !== 'object') return {};
    const result: BankProgress = {};
    for (const question of questions) {
      const stored: unknown = (data as Record<string, unknown>)[question.id];
      if (!stored || typeof stored !== 'object') continue;
      const raw = stored as Record<string, unknown>;
      const attempt = emptyAttempt(question);
      attempt.review = raw.review === true;
      // Legacy questions all have revised distractors. Keep flags, never reinterpret
      // their numeric selections as answers to the revised bank. Leave v1 untouched.
      if (!legacy && raw.revision === question.revision && typeof raw.selected === 'string' && question.choiceIds.includes(raw.selected)) {
        attempt.selected = raw.selected;
        attempt.checked = raw.checked === true;
      }
      if (attempt.selected !== undefined && typeof raw.firstCorrect === 'boolean') attempt.firstCorrect = raw.firstCorrect;
      result[question.id] = attempt;
    }
    return result;
  } catch { return {}; }
}

export function getBankProgressNotice(): string {
  try {
    const current = localStorage.getItem(bankProgressKey);
    if (current === null && localStorage.getItem(legacyBankProgressKey) !== null) {
      return 'The questions have been revised. Earlier answers were not carried over; review flags were kept for continuing questions.';
    }
    const data: unknown = JSON.parse(current ?? '{}');
    if (data && typeof data === 'object' && questionBank.some(question => {
      const raw = (data as Record<string, Partial<BankAttempt>>)[question.id];
      return raw && raw.revision !== question.revision;
    })) return 'Updated questions need a new answer. Their earlier results were cleared; review flags were kept for continuing questions.';
  } catch { /* Storage availability is reported by the page. */ }
  return '';
}
