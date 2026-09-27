import { Navigate, type RouteObject } from 'react-router';
import { AppLayout } from './AppLayout';
import { NotFoundPage } from './NotFoundPage';
import { RouteError } from './RouteError';
import { HomePage } from '../pages/home/HomePage';
import { LayersPage } from '../pages/layers/LayersPage';
import { TransmitPage } from '../pages/transmit/TransmitPage';
import { SizesPage } from '../pages/sizes/SizesPage';
import { ConceptsLayout } from '../pages/concepts/ConceptsLayout';
import { concepts } from '../pages/concepts/concepts';

/**
 * One route per intent. Paths are part of the teaching surface: a layer, detail view,
 * experiment or concept can be linked directly. The ASP.NET host falls back to index.html
 * for these paths so deep links work on reload.
 */
export const routes: RouteObject[] = [
  {
    element: <AppLayout />,
    children: [
      {
        // A pathless route keeps the header and navigation visible when a page fails.
        errorElement: <RouteError />,
        children: [
          { index: true, element: <HomePage /> },
          { path: 'layers', element: <Navigate to="/layers/network" replace /> },
          { path: 'layers/:layer/:view?', element: <LayersPage /> },
          { path: 'transmit', element: <TransmitPage /> },
          { path: 'sizes', element: <SizesPage /> },
          {
            path: 'concepts',
            element: <ConceptsLayout />,
            children: [
              { index: true, element: <Navigate to={concepts[0]!.slug} replace /> },
              ...concepts.map(concept => ({ path: concept.slug, element: <concept.Article /> }))
            ]
          },
          { path: '*', element: <NotFoundPage /> }
        ]
      }
    ]
  }
];
