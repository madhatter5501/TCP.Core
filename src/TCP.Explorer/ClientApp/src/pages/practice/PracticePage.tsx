import { useEffect, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ccnaPractice, type PracticeScenario } from '../../content/ccnaPractice';
import { ccnaLessons, type Checkpoint } from '../../content/ccnaLessons';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { emptyTopic, loadProgress, progressKey, type Attempt, type Confidence, type TopicProgress } from './practiceProgress';
import './practice.css';
import { orderedChoices } from './choiceOrder';

function Question({ id, number, question, attempt, onChange, children }: {
  id: string; number: number; question: Checkpoint; attempt?: Attempt;
  onChange: (attempt: Attempt) => void; children?: ReactNode;
}) {
  const correct = attempt?.selected === question.answer;
  return (
    <section className="practice-question" aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`}>{number === 1 ? '1. Diagnose the scenario' : `${number}. Apply it to a harder case`}</h3>
      <pre className="practice-evidence"><code>{question.evidence}</code></pre>
      <fieldset className="practice-choices">
        <legend>{question.question}</legend>
        {orderedChoices(id, question.choices).map(({ choice, index }) => (
          <label key={choice}>
            <input type="radio" name={id} checked={attempt?.selected === index} onChange={() => onChange({ selected: index, checked: false })} />
            {choice}
          </label>
        ))}
      </fieldset>
      <button className="outline-button practice-check" disabled={attempt?.selected === undefined} onClick={() => onChange({ ...attempt!, checked: true })}>Check answer {number}</button>
      {attempt?.checked && (
        <div className={`practice-answer ${correct ? 'correct' : 'incorrect'}`} role="status" aria-label={`Answer ${number} feedback`}>
          <h4>{correct ? 'Correct — check your reasoning' : 'Not quite — work through the explanation'}</h4>
          <p><strong>Answer:</strong> {question.choices[question.answer]}</p>
          <p>{question.explanation}</p>
          {children}
        </div>
      )}
    </section>
  );
}

function Exercise({ scenario, progress, onChange, onMark, onNext, hasNext, storageAvailable }: {
  scenario: PracticeScenario; progress: TopicProgress; onChange: (value: TopicProgress) => void;
  onMark: (value: Confidence | undefined) => void; onNext: () => void; hasNext: boolean; storageAvailable: boolean;
}) {
  const lesson = ccnaLessons[scenario.id]!;
  const [notice, setNotice] = useState('');
  const updateAttempt = (key: string, attempt: Attempt) => onChange({ ...progress, attempts: { ...progress.attempts, [key]: attempt } });
  const mark = (value: Confidence | undefined) => {
    onMark(value);
    setNotice(value === 'ready' ? 'Marked “Can explain”. Your topic progress has been updated.' : value === 'review' ? 'Marked “Needs review”. This topic is in your review list.' : 'Rating cleared. Your answers and notes are kept.');
  };
  return (
    <article className="panel practice-exercise" aria-labelledby="exercise-title">
      <div className="eyebrow">{scenario.topic} · 3 questions + lab</div>
      <h2 id="exercise-title" tabIndex={-1}>{scenario.title}</h2>
      <p className="practice-goal">{lesson.goal}</p>
      <div className="practice-rating-panel">
        <strong>Your understanding: {progress.confidence === 'ready' ? 'Can explain' : progress.confidence === 'review' ? 'Needs review' : 'Unrated'}</strong>
        <div className="practice-actions" role="group" aria-label="Rate your understanding">
          <button className="outline-button" aria-pressed={progress.confidence === 'review'} onClick={() => mark('review')}>Needs review</button>
          <button className="outline-button" aria-pressed={progress.confidence === 'ready'} onClick={() => mark('ready')}>I can explain this</button>
          {progress.confidence && <button className="quiet-button" onClick={() => mark(undefined)}>Clear rating</button>}
        </div>
        {notice && <p className="practice-notice" role="status" aria-label="Rating feedback">{notice}</p>}
        <span className="small-muted">{storageAvailable ? 'Ratings, answers, and notes are saved in this browser.' : 'Browser storage is unavailable. Progress is kept only until you leave this page.'}</span>
      </div>
      <label htmlFor="practice-notes" className="practice-notes-label">Your reasoning and questions to revisit</label>
      <textarea id="practice-notes" rows={3} value={progress.notes} onChange={event => onChange({ ...progress, notes: event.target.value })} placeholder="Predict the result, record the evidence, and explain what you would check next. Notes are not automatically graded." />
      <Question id={`${scenario.id}-foundation`} number={1} question={scenario} attempt={progress.attempts.foundation} onChange={attempt => updateAttempt('foundation', attempt)}>
        <h4>Work through the decision</h4>
        <ol>{lesson.reasoning.map(step => <li key={step}>{step}</li>)}</ol>
        <div className="callout"><strong>Common mistake</strong><p>{lesson.trap}</p></div>
      </Question>
      <details className="disclosure">
        <summary>Hint for question 1</summary>
        <div className="disclosure-body">{scenario.hint}</div>
      </details>
      {lesson.checkpoints.map((question, index) => (
        <Question key={index} id={`${scenario.id}-checkpoint-${index}`} number={index + 2} question={question} attempt={progress.attempts[`checkpoint-${index}`]} onChange={attempt => updateAttempt(`checkpoint-${index}`, attempt)} />
      ))}
      <section className="practice-lab" aria-labelledby="lab-title">
        <div className="eyebrow">Build, break, verify</div>
        <h3 id="lab-title">Hands-on lab task</h3>
        <p>{lesson.lab.task}</p>
        <p className="small-muted">Run this task in Packet Tracer or your own lab. Commands below are examples; this page does not execute Cisco IOS.</p>
        <pre className="practice-evidence"><code>{lesson.lab.commands}</code></pre>
        <h4>What you should verify</h4>
        <ul>{lesson.lab.verify.map(item => <li key={item}>{item}</li>)}</ul>
        <h4>Explain without looking</h4>
        <p>{scenario.next}</p>
        {scenario.explore && <Link className="inline-link" to={scenario.explore.to}>{scenario.explore.label} →</Link>}
      </section>
      <button className="outline-button practice-next" disabled={!hasNext} onClick={onNext}>Next topic →</button>
    </article>
  );
}

export function PracticePage() {
  useDocumentTitle('CCNA Practice');
  const [params, setParams] = useSearchParams();
  const [progress, setProgress] = useState(loadProgress);
  const [storageAvailable, setStorageAvailable] = useState(true);
  const [reviewOnly, setReviewOnly] = useState(false);
  useEffect(() => {
    try { localStorage.setItem(progressKey, JSON.stringify(progress)); setStorageAvailable(true); }
    catch { setStorageAvailable(false); }
  }, [progress]);
  const visible = ccnaPractice.filter(scenario => !reviewOnly || progress[scenario.id]?.confidence === 'review');
  const scenario = visible.find(item => item.id === params.get('topic')) ?? visible[0];
  const ready = Object.values(progress).filter(value => value.confidence === 'ready').length;
  const review = Object.values(progress).filter(value => value.confidence === 'review').length;
  const totalQuestions = ccnaPractice.reduce((total, item) => total + 1 + ccnaLessons[item.id]!.checkpoints.length, 0);
  const correctAnswers = ccnaPractice.reduce((total, item) => {
    const answers = [item, ...ccnaLessons[item.id]!.checkpoints];
    return total + answers.filter((q, index) => {
      const attempt = progress[item.id]?.attempts[index === 0 ? 'foundation' : `checkpoint-${index - 1}`];
      return attempt?.checked && attempt.selected === q.answer;
    }).length;
  }, 0);
  const selectTopic = (id: string) => {
    setParams(previous => { const next = new URLSearchParams(previous); next.set('topic', id); return next; });
  };
  // Move the lesson heading into view after navigation, including when filtering changes the topic.
  useEffect(() => {
    if (params.has('topic')) {
      document.getElementById('exercise-title')?.focus({ preventScroll: true });
      document.getElementById('exercise-title')?.scrollIntoView({ block: 'start' });
    }
  }, [scenario?.id]);
  const update = (id: string, value: TopicProgress) => setProgress(previous => ({ ...previous, [id]: value }));
  const index = visible.findIndex(item => item.id === scenario?.id);
  return (
    <div className="practice-page">
      <PageHeading eyebrow="Reason through the network" title="CCNA Practice" next={{ to: '/practice/bank', label: '200-question bank' }}>
        <p>12 guided lessons, 36 questions, and lab tasks. Diagnose the evidence, test your reasoning in harder cases, and keep a review list.</p>
      </PageHeading>
      <div className="practice-intro">
        <p><Link className="inline-link" to="/practice/scenarios">Try five topology scenarios: predict, diagnose, verify →</Link></p>
        <p>Study examples for CCNA 200-301 v1.1. Use the worked solutions to understand the decisions, then verify them in a lab. Self-ratings and question results measure different things.</p>
        <a className="inline-link" href="https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf">Official exam checklist ↗</a>
      </div>
      <div className="practice-progress" aria-live="polite">
        <strong>{correctAnswers} / {totalQuestions} questions correct</strong>
        <span>{ready} / {ccnaPractice.length} self-rated confident</span>
        <span>{review} need review · {ccnaPractice.length - ready - review} unrated</span>
        <span className="small-muted">{storageAvailable ? 'Progress saved in this browser, including after reload.' : 'Browser storage is unavailable; progress will not survive reload.'} These samples are not a full mock exam or an exam readiness score.</span>
      </div>
      <div className="practice-grid">
        <aside className="panel practice-list" aria-label="Practice topics">
          <label className="check-label"><input type="checkbox" checked={reviewOnly} onChange={event => setReviewOnly(event.target.checked)} />Show only topics needing review</label>
          {scenario && <div className="practice-topic-select">
            <label htmlFor="practice-topic">Choose a topic</label>
            <select id="practice-topic" value={scenario.id} onChange={event => selectTopic(event.target.value)}>
              {visible.map(item => <option key={item.id} value={item.id}>{item.title}</option>)}
            </select>
          </div>}
          <div className="practice-topic-buttons">
            {visible.map(item => (
              <button key={item.id} aria-pressed={scenario?.id === item.id} onClick={() => selectTopic(item.id)}>
                <strong>{item.title}</strong>
                <span>{item.topic}</span>
                <span className="practice-rating">{progress[item.id]?.confidence === 'ready' ? 'Can explain' : progress[item.id]?.confidence === 'review' ? 'Needs review' : 'Unrated'}</span>
              </button>
            ))}
          </div>
          {visible.length === 0 && <p>No topics marked for review. Turn off the filter to work through the lessons.</p>}
        </aside>
        {scenario ? <Exercise key={scenario.id} scenario={scenario} progress={progress[scenario.id] ?? emptyTopic()} storageAvailable={storageAvailable}
          onChange={value => update(scenario.id, value)} onMark={value => update(scenario.id, { ...(progress[scenario.id] ?? emptyTopic()), confidence: value })}
          hasNext={index + 1 < visible.length} onNext={() => { const next = visible[index + 1]; if (next) selectTopic(next.id); }} />
          : <div className="panel practice-empty">Your review list is clear. <button className="outline-button" onClick={() => setReviewOnly(false)}>Show all topics</button></div>}
      </div>
    </div>
  );
}
