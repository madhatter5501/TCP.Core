import { NavLink, Outlet, ScrollRestoration } from 'react-router';
import { useTransportStatus } from '../components/useTransportStatus';
import './layout.css';

export const primaryNav = [
  { to: '/layers', label: 'Layers' },
  { to: '/transmit', label: 'Transmit' },
  { to: '/sizes', label: 'MTU & MSS' },
  { to: '/concepts', label: 'Concepts' }
];

export function AppLayout() {
  const transport = useTransportStatus();
  return (
    <>
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <NavLink className="brand" to="/" end>
            <span className="brand-icon" aria-hidden="true">≋</span>
            <strong>TCP<span>.Core</span></strong>
            <span className="brand-divider" aria-hidden="true"></span>
            <span className="brand-label">STACK EXPLORER</span>
          </NavLink>
          <nav aria-label="Primary">
            {primaryNav.map(item => <NavLink key={item.to} to={item.to}>{item.label}</NavLink>)}
          </nav>
          <span className="transport-pill" aria-live="polite" title={transport ? `Served via ${transport.mode} · ${transport.endpoint}` : undefined}>
            {transport && <><i aria-hidden="true"></i>via {transport.mode}</>}
          </span>
        </div>
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      {/* Every initial page load has the key "default"; key those by URL so one page's scroll position isn't restored on another. */}
      <ScrollRestoration getKey={location => (location.key === 'default' ? location.pathname + location.search : location.key)} />
    </>
  );
}
