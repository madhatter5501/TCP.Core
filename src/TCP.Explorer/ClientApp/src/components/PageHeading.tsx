import type { ReactNode } from 'react';
import { Link } from 'react-router';

interface PageHeadingProps {
  eyebrow: string;
  title: string;
  /** A suggested next page, so the sections read as a path rather than a pile of tools. */
  next?: { to: string; label: string };
  children?: ReactNode;
}

export function PageHeading({ eyebrow, title, next, children }: PageHeadingProps) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {children}
      </div>
      {next && (
        <Link className="next-link" to={next.to}>
          <span>Next</span>
          <strong>{next.label} →</strong>
        </Link>
      )}
    </div>
  );
}
