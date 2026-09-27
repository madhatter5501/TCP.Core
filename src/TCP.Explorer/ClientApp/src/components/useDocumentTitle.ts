import { useEffect } from 'react';

export function useDocumentTitle(title: string) {
  useEffect(() => { document.title = `${title} · TCP.Core Stack Explorer`; }, [title]);
}
