import { orderedChoices } from './choiceOrder';
import { ccnaPractice } from '../../content/ccnaPractice';
import { ccnaLessons } from '../../content/ccnaLessons';

test('display order is stable and preserves authored answer identities', () => {
  for (const scenario of ccnaPractice) {
    const questions = [scenario, ...ccnaLessons[scenario.id]!.checkpoints];
    questions.forEach((question, i) => {
      const id = `${scenario.id}-${i === 0 ? 'foundation' : `checkpoint-${i - 1}`}`;
      const displayed = orderedChoices(id, question.choices);
      expect(displayed).toEqual(orderedChoices(id, question.choices));
      expect(displayed.map(item => item.index).sort()).toEqual([0, 1, 2]);
      expect(displayed.find(item => item.index === question.answer)?.choice).toBe(question.choices[question.answer]);
      expect(orderedChoices(id, [...question.choices].reverse()).map(item => item.choice))
        .toEqual(displayed.map(item => item.choice));
    });
  }
});

test('guided answers no longer follow the three-lesson positional pattern', () => {
  const counts = [0, 0, 0];
  for (let questionIndex = 0; questionIndex < 3; questionIndex++) {
    const positions = ccnaPractice.map(scenario => {
      const question = questionIndex === 0 ? scenario : ccnaLessons[scenario.id]!.checkpoints[questionIndex - 1]!;
      const id = `${scenario.id}-${questionIndex === 0 ? 'foundation' : `checkpoint-${questionIndex - 1}`}`;
      const position = orderedChoices(id, question.choices).findIndex(item => item.index === question.answer);
      counts[position]!++;
      return position;
    });
    for (let residue = 0; residue < 3; residue++) {
      expect(new Set(positions.filter((_, index) => index % 3 === residue)).size).toBeGreaterThan(1);
    }
  }
  for (const count of counts) {
    expect(count).toBeGreaterThanOrEqual(6);
    expect(count).toBeLessThanOrEqual(18);
  }
});
