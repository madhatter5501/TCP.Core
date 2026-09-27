import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';

afterEach(cleanup);

// jsdom has no layout or canvas. Components guard against a missing 2D context.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };
HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
window.scrollTo = () => {};
Element.prototype.scrollIntoView = () => {};
globalThis.requestAnimationFrame ??= (callback => setTimeout(callback, 0)) as typeof requestAnimationFrame;
// No ASP.NET host in tests: the transport status request simply fails and is ignored.
globalThis.fetch = (() => Promise.reject(new Error('offline'))) as typeof fetch;
