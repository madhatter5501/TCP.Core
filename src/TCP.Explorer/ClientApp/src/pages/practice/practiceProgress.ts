import { ccnaPractice } from '../../content/ccnaPractice';
import { ccnaLessons } from '../../content/ccnaLessons';

export type Confidence = 'review' | 'ready';
export interface Attempt { selected?: number; checked: boolean }
export interface TopicProgress { confidence?: Confidence; notes: string; attempts: Record<string, Attempt> }
export type PracticeProgress = Record<string, TopicProgress>;
export const progressKey = 'tcp-explorer.ccna-practice.v1';
export const emptyTopic = (): TopicProgress => ({ notes: '', attempts: {} });

/** Treat browser storage as untrusted input; ignore malformed or unknown entries. */
export function loadProgress(): PracticeProgress {
  try {
    const stored: unknown = JSON.parse(localStorage.getItem(progressKey) ?? '{}');
    if (!stored || typeof stored !== 'object') return {};
    const clean: PracticeProgress = {};
    for (const scenario of ccnaPractice) {
      const entry: unknown = (stored as Record<string, unknown>)[scenario.id];
      if (!entry || typeof entry !== 'object') continue;
      const value = entry as Record<string, unknown>;
      const topic = emptyTopic();
      if (value.confidence === 'ready' || value.confidence === 'review') topic.confidence = value.confidence;
      if (typeof value.notes === 'string') topic.notes = value.notes;
      if (value.attempts && typeof value.attempts === 'object') {
        const questions = [{ key: 'foundation', choices: scenario.choices }, ...ccnaLessons[scenario.id]!.checkpoints.map((q, i) => ({ key: `checkpoint-${i}`, choices: q.choices }))];
        for (const question of questions) {
          const attempt: unknown = (value.attempts as Record<string, unknown>)[question.key];
          if (!attempt || typeof attempt !== 'object') continue;
          const candidate = attempt as Record<string, unknown>;
          if (typeof candidate.selected === 'number' && Number.isInteger(candidate.selected) && candidate.selected >= 0 && candidate.selected < question.choices.length) {
            topic.attempts[question.key] = { selected: candidate.selected, checked: candidate.checked === true };
          }
        }
      }
      clean[scenario.id] = topic;
    }
    return clean;
  } catch { return {}; }
}
