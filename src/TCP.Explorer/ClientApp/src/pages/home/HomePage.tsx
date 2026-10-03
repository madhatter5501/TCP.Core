import type { CSSProperties } from 'react';
import { Link } from 'react-router';
import { layers } from '../../content/layers';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import './home.css';

const paths = [
  {
    to: '/layers/application', step: '01', kind: 'Understand', title: 'Walk the layers',
    body: 'Follow application bytes down to the wire and back. Each layer’s purpose, header fields, gotchas, and the TCP.Core files that implement it.',
    cta: 'Explore the stack'
  },
  {
    to: '/transmit', step: '02', kind: 'Observe', title: 'Transmit real packets',
    body: 'Run TCP.Core on two in-memory hosts. Drop, corrupt and fragment traffic, then inspect every captured frame byte by byte.',
    cta: 'Run an experiment'
  },
  {
    to: '/sizes', step: '03', kind: 'Experiment', title: 'Size things up',
    body: 'Change MTU, MSS, options and VLAN tags to see how many bytes each header costs, and when IPv4 must fragment.',
    cta: 'Open the MTU & MSS lab'
  },
  {
    to: '/concepts', step: '04', kind: 'Learn', title: 'Keep the names straight',
    body: 'Frames, datagrams, segments, plus an A–Z glossary of every abbreviation: the vocabulary that trips everyone up, explained against this implementation.',
    cta: 'Read the concepts'
  }
];

export function HomePage() {
  useDocumentTitle('Overview');
  return (
    <div className="home">
      <section className="hero">
        <div>
          <div className="eyebrow">From application to wire</div>
          <h1>What’s inside a packet?</h1>
          <p>A field guide to TCP.Core: a TCP/IP stack written from scratch in C#. Follow the layers, unpack the headers, and watch the real implementation move bytes.</p>
          <div className="hero-actions">
            <Link className="hero-primary" to="/layers/application">Start with the layers →</Link>
            <Link className="quiet-button" to="/transmit">or jump to a live transmission</Link>
          </div>
        </div>
        <ol className="hero-stack" aria-label="The five layers">
          {layers.map(layer => (
            <li key={layer.slug}>
              <Link to={`/layers/${layer.slug}`} style={{ '--layer-color': layer.color } as CSSProperties}>
                <span className="hero-stack-number">{layer.number}</span>
                <span className="hero-stack-name">{layer.name}</span>
                <span className="hero-stack-pdu">{layer.pdu}</span>
              </Link>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="paths-title">
        <h2 id="paths-title" className="section-label">Choose what you want to do</h2>
        <div className="path-grid">
          {paths.map(path => (
            <Link key={path.to} to={path.to} className="path-card">
              <span className="path-kind"><span>{path.step}</span>{path.kind}</span>
              <h3>{path.title}</h3>
              <p>{path.body}</p>
              <span className="path-cta">{path.cta} →</span>
            </Link>
          ))}
        </div>
      </section>

      <section className="home-notes">
        <p><strong>Five-layer teaching model.</strong> L5–7 groups the OSI session, presentation, and application layers. The four-layer TCP/IP model combines link and physical. ICMP belongs alongside IPv4 at L3; ARP connects IPv4 next hops to L2 addresses.</p>
        <p><strong>Source-grounded, educational.</strong> Implementation labels reflect the checked-in source, not a standards-compliance claim. Transmissions execute real TCP.Core code on an in-memory link; the MTU &amp; MSS lab is a byte-accounting model.</p>
      </section>
    </div>
  );
}
