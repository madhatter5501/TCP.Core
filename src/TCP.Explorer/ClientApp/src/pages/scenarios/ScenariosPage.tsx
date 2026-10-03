import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ccnaScenarios, type NetworkScenario } from '../../content/ccnaScenarios';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import { orderedChoices } from '../practice/choiceOrder';
import '../practice/practice.css';
import './scenarios.css';

const labAsset = (id: string, file: string) => `${import.meta.env.BASE_URL}labs/ccna/${id}/${file}`;

const supportingCaptures: Record<string, string[]> = {
  "vlan": [
    "fault-traffic.png",
    "repaired-trunk.png"
  ],
  "routes": [
    "baseline-traffic.png",
    "fault-policy.png",
    "fault-traffic.png",
    "repaired-traffic.png"
  ],
  "pat": [
    "baseline-client-a.png",
    "baseline-client-b.png",
    "repaired-client-a.png",
    "repaired-client-b.png"
  ],
  "acl": [
    "baseline-admin.png",
    "repaired-admin.png",
    "repaired-icmp.png",
    "server-service.png"
  ],
  "ospf": [
    "repaired-r2.png"
  ]
};

function Topology({ scenario }: { scenario: NetworkScenario }) {
  return <figure className="scenario-topology">
    {scenario.id === 'routes' ? <svg viewBox="0 0 900 260" role="img" aria-label="PC-A connects to R1. R1 has separate paths through R2 and R3 to the server LAN.">
      <line x1="150" y1="130" x2="240" y2="130" />
      <line x1="380" y1="130" x2="480" y2="55" /><line x1="380" y1="130" x2="480" y2="205" />
      <line x1="620" y1="55" x2="745" y2="130" /><line x1="620" y1="205" x2="745" y2="130" />
      <text x="425" y="38" textAnchor="middle">198.51.100.0/30</text>
      <text x="425" y="244" textAnchor="middle">198.51.100.4/30</text>
      {[[15, 105, 'PC-A'], [240, 105, 'R1'], [480, 30, 'R2'], [480, 180, 'R3'], [745, 105, 'Server LAN']].map(([x, y, label]) => <g key={label}>
        <rect x={x} y={y} width="140" height="50" rx="10" />
        <text x={Number(x) + 70} y={Number(y) + 30} textAnchor="middle" className="scenario-node">{label}</text>
      </g>)}
    </svg> : <svg viewBox="0 0 900 150" role="img" aria-label={`Topology overview: ${scenario.nodes.join(' to ')}`}>
      {scenario.links.map((link, i) => <g key={i}>
        <line x1={165 + i * 225} y1="80" x2={225 + i * 225} y2="80" />
        <text x={195 + i * 225} y="42" textAnchor="middle">{link}</text>
      </g>)}
      {scenario.nodes.map((node, i) => <g key={i}>
        <rect x={15 + i * 225} y="55" width="150" height="50" rx="10" />
        <text x={90 + i * 225} y="85" textAnchor="middle" className="scenario-node">{node}</text>
      </g>)}
    </svg>}
    <figcaption>{scenario.topology}</figcaption>
  </figure>;
}

function labText(scenario: NetworkScenario) {
  return `${scenario.title}\nCCNA topics ${scenario.objective}\n\nOriginal study scenario. Configuration examples and question evidence are illustrative.\n\nTOPOLOGY\n${scenario.topology}\n\nWORKING BASELINE\n${scenario.baseline}\n\nDELIBERATE FAULT\n${scenario.fault}\n\nREPAIR\n${scenario.repair}\n\nVERIFY\n${scenario.checks.map(check => '- ' + check).join('\n')}\n`;
}

function Exercise({ scenario }: { scenario: NetworkScenario }) {
  const [step, setStep] = useState(0);
  const [answers, setAnswers] = useState<Record<number, { selected: string; checked: boolean; firstCorrect?: boolean }>>({});
  const question = scenario.questions[step]!;
  const captureState = step === 0 ? (['routes', 'acl'].includes(scenario.id) ? 'fault' : 'baseline') : step === 1 ? 'fault' : 'repaired';
  const attempt = answers[step];
  const choices = orderedChoices(`${scenario.id}-${question.phase}`, [question.correct, ...question.distractors]);
  const checked = Object.values(answers).filter(a => a.firstCorrect !== undefined).length;
  const firstCorrect = Object.values(answers).filter(a => a.firstCorrect).length;
  return <article className="panel practice-exercise">
    <p className="eyebrow">Topics {scenario.objective} · 3 questions</p>
    <h2>{scenario.title}</h2>
    <p className="practice-goal">{scenario.brief}</p>
    <Topology scenario={scenario} />
    <p className="small-muted">Original topology diagrams and authored configuration examples. Question evidence is illustrative.</p>
    <div className="scenario-stages" role="group" aria-label="Scenario stages">
      {scenario.questions.map((q, i) => <button className="outline-button" key={q.phase} aria-pressed={step === i} onClick={() => setStep(i)}>{i + 1}. {q.phase}</button>)}
    </div>
    <section className="practice-question" aria-label={`${question.phase} question`}>
      <h3>{question.phase}</h3>
      <pre className="practice-evidence"><code>{question.evidence}</code></pre>
      <fieldset className="practice-choices"><legend>{question.prompt}</legend>
        {choices.map(({ choice }) => <label key={choice}>
          <input type="radio" name={`${scenario.id}-${step}`} checked={attempt?.selected === choice} onChange={() => setAnswers(previous => ({ ...previous, [step]: { ...previous[step], selected: choice, checked: false } }))} />
          <span>{choice}</span>
        </label>)}
      </fieldset>
      <button className="outline-button practice-check" disabled={!attempt} onClick={() => setAnswers(previous => ({ ...previous, [step]: { ...attempt!, checked: true, firstCorrect: attempt!.firstCorrect ?? attempt!.selected === question.correct } }))}>Check answer</button>
      {attempt?.checked && <div className={`practice-answer ${attempt.selected === question.correct ? 'correct' : 'incorrect'}`} role="status" aria-label="Scenario feedback">
        <h4>{attempt.selected === question.correct ? 'Correct' : 'Not quite — review the evidence'}</h4>
        <p><strong>Best answer:</strong> {question.correct}</p><p>{question.explanation}</p>
      </div>}
      <p className="small-muted">{firstCorrect} / {checked} correct on first check. Answers stay while this scenario is open.</p>
      <div className="practice-actions">
        <button className="outline-button" disabled={step === 0} onClick={() => setStep(step - 1)}>Previous stage</button>
        <button className="outline-button" disabled={step === 2} onClick={() => setStep(step + 1)}>Next stage</button>
      </div>
    </section>
    <details className="scenario-captures"><summary>View Packet Tracer captures</summary>
      <p>Actual lab runs captured in Packet Tracer 9.0.1. Question excerpts above are condensed study examples. Open an image to inspect the full-size output; allow convergence and generate fresh traffic when reopening a lab.</p>
      {['topology', captureState].map(name => <figure key={name}>
        <a href={labAsset(scenario.id, `${name}.png`)} target="_blank" rel="noreferrer"><img src={labAsset(scenario.id, `${name}.png`)} alt={`${scenario.title}: ${name} capture`} /></a>
      </figure>)}
      {supportingCaptures[scenario.id]?.filter(file => file.startsWith(`${captureState}-`)).map(file => <figure key={file}>
        <a href={labAsset(scenario.id, file)} target="_blank" rel="noreferrer"><img src={labAsset(scenario.id, file)} alt={`${scenario.title}: ${file.replace('.png', '').replaceAll('-', ' ')} supporting evidence`} loading="lazy" /></a>
      </figure>)}
      <ul>{['baseline', 'fault', 'repaired'].map(name => <li key={name}><a className="inline-link" href={labAsset(scenario.id, `${name}.pkt`)} download={`${scenario.id}-${name}.pkt`}>Download {name} lab (.pkt)</a></li>)}</ul>
    </details>
    <details className="practice-lab"><summary>Build, break, and repair this lab — includes solutions</summary>
      <p>Use compatible devices in an isolated practice network. Establish a working baseline, introduce the fault, and verify the repair. Allow ARP, STP, and routing to converge; start fresh traffic for NAT and ACL checks.</p>
      <a className="inline-link" download={`${scenario.id}-lab.txt`} href={`data:text/plain;charset=utf-8,${encodeURIComponent(labText(scenario))}`}>Download lab instructions</a>
      <h4>1. Establish the baseline</h4><pre className="practice-evidence"><code>{scenario.baseline}</code></pre>
      <h4>2. Introduce the fault</h4><pre className="practice-evidence"><code>{scenario.fault}</code></pre>
      <h4>3. Repair the fault</h4><pre className="practice-evidence"><code>{scenario.repair}</code></pre>
      <h4>4. Verify</h4><ul>{scenario.checks.map(check => <li key={check}>{check}</li>)}</ul>
    </details>
  </article>;
}

export function ScenariosPage() {
  useDocumentTitle('CCNA topology scenarios');
  const [params, setParams] = useSearchParams();
  const scenario = ccnaScenarios.find(item => item.id === params.get('scenario')) ?? ccnaScenarios[0]!;
  return <div className="practice-page">
    <PageHeading eyebrow="Follow the evidence" title="Topology scenarios" next={{ to: '/practice/bank', label: '200-question bank' }}>
      <p>Five network cases. Predict the behavior, diagnose the fault, and choose how to verify the repair.</p>
    </PageHeading>
    <p className="practice-intro">15 original study questions for CCNA v1.1. <Link className="inline-link" to="/practice">Back to guided lessons →</Link></p>
    <div className="scenario-picker"><label htmlFor="scenario-select">Choose a scenario</label>
      <select id="scenario-select" value={scenario.id} onChange={event => setParams({ scenario: event.target.value })}>
        {ccnaScenarios.map(item => <option key={item.id} value={item.id}>{item.title}</option>)}
      </select>
    </div>
    <Exercise key={scenario.id} scenario={scenario} />
  </div>;
}
