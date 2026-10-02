export type Difficulty = 'Understand' | 'Apply' | 'Troubleshoot';
export interface QuestionSpec {
  id: string;
  objective: string;
  prompt: string;
  correct: string;
  distractors: [string, string, string];
  explanation: string;
  evidence: string;
  difficulty: Difficulty;
}
export interface BankQuestion {
  id: string;
  revision: string;
  section: string;
  objective: string;
  prompt: string;
  choices: string[];
  choiceIds: string[];
  answer: number;
  explanation: string;
  evidence: string;
  difficulty: Difficulty;
}
/** Author questions with explicit identities and a correct answer; assembly varies its displayed position. */
export function q(id: string, objective: string, prompt: string, correct: string, distractors: [string, string, string], explanation: string, evidence = '', difficulty: Difficulty = evidence ? 'Apply' : 'Understand'): QuestionSpec {
  return { id, objective, prompt, correct, distractors, explanation, evidence, difficulty };
}
export const examSections = [
  { id: 'fundamentals', title: 'Network fundamentals', weight: 20, count: 40, prefix: '1', objectives: 13 },
  { id: 'access', title: 'Network access', weight: 20, count: 40, prefix: '2', objectives: 9 },
  { id: 'connectivity', title: 'IP connectivity', weight: 25, count: 50, prefix: '3', objectives: 5 },
  { id: 'services', title: 'IP services', weight: 10, count: 20, prefix: '4', objectives: 9 },
  { id: 'security', title: 'Security fundamentals', weight: 15, count: 30, prefix: '5', objectives: 10 },
  { id: 'automation', title: 'Automation and programmability', weight: 10, count: 20, prefix: '6', objectives: 7 }
] as const;
