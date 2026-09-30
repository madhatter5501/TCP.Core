import { questionBank } from '../../content/questionBank';

export interface BankAttempt {
  selected?: number;
  checked: boolean;
  review: boolean;
  firstCorrect?: boolean;
}
export type BankProgress = Record<string, BankAttempt>;
export const bankProgressKey = 'tcp-explorer.ccna-bank.v1';
export const emptyAttempt = (): BankAttempt => ({ checked: false, review: false });

export function loadBankProgress(): BankProgress {
  try {
    const data: unknown = JSON.parse(localStorage.getItem(bankProgressKey) ?? '{}');
    if (!data || typeof data !== 'object') return {};
    const result: BankProgress = {};
    for (const question of questionBank) {
      const stored: unknown = (data as Record<string, unknown>)[question.id];
      if (!stored || typeof stored !== 'object') continue;
      const raw = stored as Record<string, unknown>;
      const attempt = emptyAttempt();
      attempt.review = raw.review === true;
      if (typeof raw.selected === 'number' && Number.isInteger(raw.selected) && raw.selected >= 0 && raw.selected < question.choices.length) {
        attempt.selected = raw.selected;
        attempt.checked = raw.checked === true;
      }
      if (attempt.selected !== undefined && typeof raw.firstCorrect === 'boolean') attempt.firstCorrect = raw.firstCorrect;
      result[question.id] = attempt;
    }
    return result;
  } catch { return {}; }
}
