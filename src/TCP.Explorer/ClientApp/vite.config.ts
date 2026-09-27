import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// The ASP.NET host serves the build from ../wwwroot and answers /api. During `npm run dev`,
// Vite serves the UI and forwards /api to a running `dotnet run --project src/TCP.Explorer`.
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../wwwroot', emptyOutDir: true },
  server: { proxy: { '/api': 'http://localhost:5097' } },
  test: { environment: 'jsdom', globals: true, setupFiles: './src/test/setup.ts' }
});
