import { fundamentals } from './fundamentals';
import { access } from './access';
import { connectivity } from './connectivity';
import { services } from './services';
import { security } from './security';
import { automation } from './automation';
import { examSections, type BankQuestion } from './types';

const specs = { fundamentals, access, connectivity, services, security, automation };
/** Stable IDs keep saved attempts attached to the same authored question. */
export const questionBank: BankQuestion[] = examSections.flatMap(section => specs[section.id].map((spec, index) => {
  const authored = [spec.correct, ...spec.distractors];
  const offset = index % authored.length;
  const choices = authored.slice(offset).concat(authored.slice(0, offset));
  return {
    id: `${section.id}-${String(index + 1).padStart(3, '0')}`,
    section: section.id, objective: spec.objective, prompt: spec.prompt,
    choices, answer: choices.indexOf(spec.correct), evidence: spec.evidence,
    explanation: spec.explanation, difficulty: spec.difficulty
  };
}));
export { examSections } from './types';
