import { defineConfig, devices } from '@playwright/test';

// Drives the REAL panel: globalSetup builds/starts the forgepanel binary, waits
// for /healthz, completes first-run setup, and writes credentials to .auth.json.
// The panel serves the SvelteKit SPA (see the SPA-serving fix), so these are true
// end-to-end UI tests, desktop + mobile.
const PORT = Number(process.env.FP_E2E_PORT || 24700);
// HTTPS by default (self-signed with no domain) — tests accept the self-signed cert.
export const BASE_URL = `https://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  use: { baseURL: BASE_URL, headless: true, ignoreHTTPSErrors: true },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 5'] } },
  ],
});
