import { questionBank, examSections } from './index';

test('the bank has 200 distinct original questions at the blueprint domain weights', () => {
  expect(questionBank).toHaveLength(200);
  expect(new Set(questionBank.map(q => q.id)).size).toBe(200);
  expect(new Set(questionBank.map(q => q.prompt)).size).toBe(200);
  for (const section of examSections) {
    expect(questionBank.filter(q => q.section === section.id)).toHaveLength(section.count);
    expect(section.count).toBe(section.weight * 2);
  }
});

test('all 53 main blueprint objectives have questions and usable answer explanations', () => {
  const expected = examSections.flatMap(section => Array.from({ length: section.objectives }, (_, i) => `${section.prefix}.${i + 1}`));
  expect(new Set(questionBank.map(q => q.objective))).toEqual(new Set(expected));
  for (const q of questionBank) {
    expect(q.choices).toHaveLength(4);
    expect(new Set(q.choices).size).toBe(4);
    expect(q.answer).toBeGreaterThanOrEqual(0);
    expect(q.answer).toBeLessThan(4);
    expect(q.explanation.length).toBeGreaterThan(80);
    const section = examSections.find(section => section.id === q.section)!;
    expect(q.objective.startsWith(`${section.prefix}.`)).toBe(true);
  }
});

test('subnet answer keys include correct boundaries and cross-octet calculations', () => {
  const answers = questionBank.filter(q => q.objective === '1.6').map(q => q.choices[q.answer]);
  expect(answers).toContain('192.0.2.64 and 192.0.2.95');
  expect(answers).toContain('/26');
  expect(answers).toContain('10.7.32.1 through 10.7.47.254');
  expect(answers).toContain('10.0.0.0/26, 10.0.0.64/27, 10.0.0.96/28');
});
