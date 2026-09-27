import { NavLink, Outlet } from 'react-router';
import { concepts } from './concepts';
import './concepts.css';

export function ConceptsLayout() {
  return (
    <div className="concepts">
      <aside className="concepts-nav" aria-label="Concepts">
        <div className="eyebrow">Learn · Concepts</div>
        <nav>
          {concepts.map(concept => (
            <NavLink key={concept.slug} to={`/concepts/${concept.slug}`}>
              <strong>{concept.title}</strong>
              <span>{concept.summary}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sources">
          <span>Further reading</span>
          <a href="https://www.rfc-editor.org/rfc/rfc768.html" target="_blank" rel="noreferrer">UDP · RFC 768 ↗</a>
          <a href="https://www.rfc-editor.org/rfc/rfc791.html" target="_blank" rel="noreferrer">IPv4 · RFC 791 ↗</a>
          <a href="https://www.rfc-editor.org/rfc/rfc9293.html" target="_blank" rel="noreferrer">TCP · RFC 9293 ↗</a>
          <a href="https://www.rfc-editor.org/rfc/rfc6691.html" target="_blank" rel="noreferrer">MSS · RFC 6691 ↗</a>
          <a href="https://www.rfc-editor.org/rfc/rfc1191.html" target="_blank" rel="noreferrer">Path MTU · RFC 1191 ↗</a>
        </div>
      </aside>
      <article className="concept-article">
        <Outlet />
      </article>
    </div>
  );
}
