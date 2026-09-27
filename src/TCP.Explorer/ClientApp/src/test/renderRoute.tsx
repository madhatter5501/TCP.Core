import { render } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router';
import { routes } from '../app/routes';

export function renderRoute(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  return { router, ...render(<RouterProvider router={router} />) };
}
