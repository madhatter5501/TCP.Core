import { fundamentals } from './fundamentals';
import { access } from './access';
import { connectivity } from './connectivity';
import { services } from './services';
import { security } from './security';
import { automation } from './automation';
import { examSections, type BankQuestion, type QuestionSpec } from './types';

const specs = { fundamentals, access, connectivity, services, security, automation };
/** Content fingerprint, not a security hash. Array order is deliberately excluded. */
function fingerprint(value: string): string {
  let hash = 0xcbf29ce484222325n;
  for (const character of value) {
    hash ^= BigInt(character.codePointAt(0)!);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, '0');
}

export function assembleQuestion(spec: QuestionSpec, section: string): BankQuestion {
  const authored = [spec.correct, ...spec.distractors];
  // Sort by independent ID/choice fingerprints, rather than the question's ordinal.
  // This is reproducible across reloads and unaffected by the study queue order.
  const choices = [...authored].sort((a, b) => {
    const left = fingerprint(`${spec.id}\0${a}`);
    const right = fingerprint(`${spec.id}\0${b}`);
    return left < right ? -1 : left > right ? 1 : a < b ? -1 : a > b ? 1 : 0;
  });
  return {
    id: spec.id,
    revision: fingerprint(JSON.stringify([spec.objective, spec.prompt, spec.correct, [...authored].sort(), spec.evidence, spec.explanation])),
    section, objective: spec.objective, prompt: spec.prompt,
    // Choice text is its identity; selection no longer depends on a display index.
    choices, choiceIds: [...choices], answer: choices.indexOf(spec.correct), evidence: spec.evidence,
    explanation: spec.explanation, difficulty: spec.difficulty
  };
}

export const questionBank: BankQuestion[] = examSections.flatMap(section => specs[section.id].map(spec => assembleQuestion(spec, section.id)));
export { examSections } from './types';
