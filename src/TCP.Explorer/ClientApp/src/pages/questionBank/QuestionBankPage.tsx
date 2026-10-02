import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import { questionBank, examSections } from '../../content/questionBank';
import type { BankQuestion } from '../../content/questionBank/types';
import { bankReviewDate, blueprintStatus, blueprintUrl, examTransitionUrl, topicReferences } from '../../content/questionBank/references';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { bankProgressKey, emptyAttempt, loadBankProgress, getBankProgressNotice, type BankProgress } from './bankProgress';
import './bank.css';

type Status = 'all' | 'unanswered' | 'incorrect' | 'review';
interface Filters { section: string; status: Status; difficulty: string; search: string }
const defaultFilters: Filters = { section: 'all', status: 'all', difficulty: 'all', search: '' };

function QuestionEvidence({ evidence }: { evidence: string }) {
  if (!evidence.startsWith('Illustrative WLAN GUI\n')) return <pre className="bank-evidence"><code>{evidence}</code></pre>;
  return <section className="bank-gui" aria-label="Illustrative WLAN configuration">
    <h3>Illustrative WLAN configuration</h3>
    <dl>{evidence.split('\n').slice(1).map((line, i) => {
      const colon = line.indexOf(':');
      return <div key={i}><dt>{colon < 0 ? 'Context' : line.slice(0, colon)}</dt><dd>{colon < 0 ? line : line.slice(colon + 1).trim()}</dd></div>;
    })}</dl>
  </section>;
}

function matches(question: BankQuestion, filters: Filters, progress: BankProgress) {
  const attempt = progress[question.id];
  return (filters.section === 'all' || question.section === filters.section)
    && (filters.difficulty === 'all' || question.difficulty === filters.difficulty)
    && (filters.status === 'all'
      || (filters.status === 'unanswered' && attempt?.firstCorrect === undefined)
      || (filters.status === 'incorrect' && attempt?.checked && attempt.selected !== question.choiceIds[question.answer])
      || (filters.status === 'review' && attempt?.review))
    && `${question.prompt} ${question.evidence} ${question.objective}`.toLowerCase().includes(filters.search.trim().toLowerCase());
}

export function QuestionBankPage() {
  useDocumentTitle('200-question CCNA Bank');
  const [params, setParams] = useSearchParams();
  const focusRequested = useRef(params.has('q'));
  const [progress, setProgress] = useState(() => loadBankProgress());
  const [storageAvailable, setStorageAvailable] = useState(true);
  const [progressNotice] = useState(getBankProgressNotice);
  const [filters, setFilters] = useState(defaultFilters);
  // Capture a study queue when filters change, so an answer does not disappear before its explanation is read.
  const [queue, setQueue] = useState(() => questionBank.map(q => q.id));
  const [notice, setNotice] = useState('');
  useEffect(() => {
    try { localStorage.setItem(bankProgressKey, JSON.stringify(progress)); setStorageAvailable(true); }
    catch { setStorageAvailable(false); }
  }, [progress]);
  const requested = params.get('q');
  const currentId = requested && queue.includes(requested) ? requested : queue[0];
  const question = questionBank.find(q => q.id === currentId);
  const index = queue.indexOf(currentId ?? '');
  const attempt = question ? progress[question.id] ?? emptyAttempt(question) : emptyAttempt();
  const section = examSections.find(section => section.id === question?.section);
  const answered = Object.values(progress).filter(a => a.firstCorrect !== undefined).length;
  const firstCorrect = Object.values(progress).filter(a => a.firstCorrect === true).length;
  const currentCorrect = questionBank.filter(q => progress[q.id]?.checked && progress[q.id]?.selected === q.choiceIds[q.answer]).length;
  const reviewCount = Object.values(progress).filter(a => a.review).length;
  const incorrectCount = questionBank.filter(q => progress[q.id]?.checked && progress[q.id]?.selected !== q.choiceIds[q.answer]).length;
  const nextUnanswered = queue.slice(index + 1).concat(queue.slice(0, index)).find(id => progress[id]?.firstCorrect === undefined);

  const changeFilters = (next: Filters) => {
    focusRequested.current = false;
    const ids = questionBank.filter(q => matches(q, next, progress)).map(q => q.id);
    setFilters(next); setQueue(ids); setNotice('');
    setParams(previous => { const updated = new URLSearchParams(previous); if (ids[0]) updated.set('q', ids[0]); else updated.delete('q'); return updated; }, { replace: true });
  };
  const selectQuestion = (id: string | undefined) => {
    if (!id) return;
    focusRequested.current = true;
    setParams(previous => { const updated = new URLSearchParams(previous); updated.set('q', id); return updated; });
    setNotice('');
  };
  useEffect(() => {
    if (focusRequested.current) {
      document.getElementById('bank-question-title')?.focus({ preventScroll: true });
      document.getElementById('bank-question-title')?.scrollIntoView({ block: 'start' });
      focusRequested.current = false;
    }
  }, [currentId]);
  const updateAttempt = (value: typeof attempt) => {
    if (question) setProgress(previous => ({ ...previous, [question.id]: value }));
  };
  const shuffle = () => {
    const shuffled = [...queue];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j]!, shuffled[i]!];
    }
    setQueue(shuffled); selectQuestion(shuffled[0]);
    setNotice('Study queue shuffled. Your saved answers are kept.');
  };

  return (
    <div className="bank-page">
      <PageHeading eyebrow="CCNA 200-301 v1.1" title="200-question bank" next={{ to: '/practice', label: 'Guided lessons' }}>
        <p>Study questions mapped to all six exam domains. Calculate, interpret illustrative configurations, and troubleshoot before reading the explanation.</p>
      </PageHeading>
      {progressNotice && <p className="bank-notice" role="status">{progressNotice}</p>}
      <div className="bank-summary" aria-live="polite">
        <strong>{answered} / 200 answered</strong>
        <span>{firstCorrect} / {answered} correct on first check</span>
        <span>{currentCorrect} currently correct</span>
        <span>{incorrectCount} incorrect · {reviewCount} saved for review</span>
      </div>
      <p className="small-muted">{storageAvailable ? 'Answers and review flags are saved in this browser. First-check results stay recorded when you retry.' : 'Browser storage is unavailable. Progress lasts only while this page stays open.'} Revised questions require a new answer. These practice questions are not actual exam items or Cisco-endorsed material. Results are not a validated prediction of exam performance.</p>
      <p className="small-muted">Examples and configuration panels are illustrative, not live device output. Parent topic tags show study samples, not complete blueprint coverage or demonstrated lab skills. Supplement this bank with configuration labs. Content review: <time dateTime={bankReviewDate}>October 2, 2026</time>. <a className="inline-link" href={blueprintUrl}>View Cisco’s topic checklist ↗</a></p>
      <p className="small-muted">{blueprintStatus()} <a className="inline-link" href={examTransitionUrl}>Cisco’s exam transition dates ↗</a></p>
      <div className="bank-sections" role="group" aria-label="Exam sections">
        {examSections.map(item => {
          const questions = questionBank.filter(q => q.section === item.id);
          const checked = questions.filter(q => progress[q.id]?.firstCorrect !== undefined).length;
          const correct = questions.filter(q => progress[q.id]?.firstCorrect === true).length;
          return <button key={item.id} aria-pressed={filters.section === item.id} onClick={() => changeFilters({ ...filters, section: item.id })}>
            <span>{item.weight}% of blueprint · {item.count} questions</span>
            <strong>{item.title}</strong>
            <span>{checked} answered · {correct} correct on first check</span>
          </button>;
        })}
      </div>
      <div className="panel bank-filters">
        <div><label htmlFor="bank-section">Section</label><select id="bank-section" value={filters.section} onChange={e => changeFilters({ ...filters, section: e.target.value })}>
          <option value="all">All sections (200)</option>{examSections.map(item => <option key={item.id} value={item.id}>{item.title} ({item.count})</option>)}
        </select></div>
        <div><label htmlFor="bank-status">Practice queue</label><select id="bank-status" value={filters.status} onChange={e => changeFilters({ ...filters, status: e.target.value as Status })}>
          <option value="all">All questions</option><option value="unanswered">Unanswered</option><option value="incorrect">Incorrect answers ({incorrectCount})</option><option value="review">Saved for review ({reviewCount})</option>
        </select></div>
        <div><label htmlFor="bank-difficulty">Question style</label><select id="bank-difficulty" value={filters.difficulty} onChange={e => changeFilters({ ...filters, difficulty: e.target.value })}>
          <option value="all">All styles</option><option>Understand</option><option>Apply</option><option>Troubleshoot</option>
        </select></div>
        <div><label htmlFor="bank-search">Search questions or topic codes</label><input id="bank-search" type="search" value={filters.search} onChange={e => changeFilters({ ...filters, search: e.target.value })} placeholder="e.g. OSPF, DHCP, 3.3" /></div>
      </div>
      <div className="bank-queue-bar">
        <span>{queue.length} questions in this queue</span>
        <button className="outline-button" disabled={queue.length < 2} onClick={shuffle}>Shuffle queue</button>
        <button className="quiet-button" onClick={() => changeFilters(filters)}>Refresh queue</button>
        <span className="small-muted">Answers stay visible until you move on. Refresh the queue to update filter matches.</span>
      </div>
      {notice && <p className="bank-notice" role="status" aria-label="Queue feedback">{notice}</p>}
      {question ? (
        <article className="panel bank-question" aria-labelledby="bank-question-title">
          <div className="bank-question-meta"><span>{section?.title}</span><span>Topic {question.objective}</span><span>{question.difficulty}</span><span>{question.id}</span></div>
          <div className="bank-question-controls">
            <label htmlFor="bank-jump">Question in queue</label>
            <select id="bank-jump" value={question.id} onChange={e => selectQuestion(e.target.value)}>
              {queue.map((id, i) => <option key={id} value={id}>{i + 1} / {queue.length} · {id}{progress[id]?.review ? ' · Review' : ''}</option>)}
            </select>
            <button className="outline-button" aria-pressed={attempt.review} onClick={() => {
              updateAttempt({ ...attempt, review: !attempt.review });
              setNotice(attempt.review ? 'Removed from your review list.' : 'Saved to your review list.');
            }}>{attempt.review ? 'Saved for review ✓' : 'Save for review'}</button>
          </div>
          <h2 id="bank-question-title" tabIndex={-1}>{question.prompt}</h2>
          {question.evidence && <QuestionEvidence evidence={question.evidence} />}
          <fieldset className="bank-choices"><legend className="bank-choice-legend">Choose the best answer</legend>
            {question.choices.map((choice, i) => <label key={choice}>
              <input type="radio" name={question.id} checked={attempt.selected === question.choiceIds[i]} onChange={() => { updateAttempt({ ...attempt, selected: question.choiceIds[i], checked: false }); setNotice(''); }} />
              <span className="bank-letter" aria-hidden="true">{String.fromCharCode(65 + i)}</span><span>{choice}</span>
            </label>)}
          </fieldset>
          <button className="outline-button bank-check" disabled={attempt.selected === undefined} onClick={() => updateAttempt({ ...attempt, checked: true, firstCorrect: attempt.firstCorrect ?? (attempt.selected === question.choiceIds[question.answer]) })}>Check answer</button>
          {attempt.checked && <div className={`bank-answer ${attempt.selected === question.choiceIds[question.answer] ? 'correct' : 'incorrect'}`} role="status" aria-label="Answer feedback">
            <h3>{attempt.selected === question.choiceIds[question.answer] ? 'Correct' : 'Not quite — review the reasoning'}</h3>
            <p><strong>Best answer:</strong> {question.choices[question.answer]}</p>
            <p>{question.explanation}</p>
            <p className="small-muted">Topic references: {topicReferences(question.objective).map((reference, i) => <span key={reference.url}>{i > 0 && ' · '}<a className="inline-link" href={reference.url}>{reference.title} ↗</a></span>)}</p>
            <p className="small-muted">Explain why the other choices do not fit before moving on. Changing your choice lets you retry; your first-check result is retained.</p>
          </div>}
          <div className="bank-pagination">
            <button className="outline-button" disabled={index <= 0} onClick={() => selectQuestion(queue[index - 1])}>← Previous</button>
            <span>{index + 1} / {queue.length}</span>
            <button className="outline-button" disabled={index >= queue.length - 1} onClick={() => selectQuestion(queue[index + 1])}>Next →</button>
            <button className="quiet-button" disabled={!nextUnanswered} onClick={() => selectQuestion(nextUnanswered)}>Next unanswered</button>
          </div>
        </article>
      ) : <div className="panel bank-empty"><h2>No questions match these filters</h2><p>Try another section or clear the filters to return to the full bank.</p><button className="outline-button" onClick={() => changeFilters(defaultFilters)}>Show all 200 questions</button></div>}
    </div>
  );
}
