import { Link, useRouteError } from 'react-router';
import { PageHeading } from '../components/PageHeading';

/** Shown inside the layout when a page throws while rendering, instead of React Router's developer screen. */
export function RouteError() {
  const error = useRouteError();
  return (
    <PageHeading eyebrow="Checksum mismatch" title="This page failed to render.">
      <p>{error instanceof Error ? error.message : 'An unexpected error occurred.'} Try <Link className="inline-link" to="/">the overview</Link> or reload the page.</p>
    </PageHeading>
  );
}
