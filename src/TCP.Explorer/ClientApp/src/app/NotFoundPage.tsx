import { Link } from 'react-router';
import { PageHeading } from '../components/PageHeading';
import { useDocumentTitle } from '../components/useDocumentTitle';

export function NotFoundPage() {
  useDocumentTitle('Not found');
  return (
    <PageHeading eyebrow="404 · No route to host" title="Nothing at this address.">
      <p>Like an IP datagram with an unknown destination, this request has nowhere to go. <Link className="inline-link" to="/">Start from the overview</Link>.</p>
    </PageHeading>
  );
}
