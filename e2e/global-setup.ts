import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The panel serves HTTPS by default (self-signed with no domain). Accept the
// self-signed cert for the local health/setup calls in this test harness.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const PORT = Number(process.env.FP_E2E_PORT || 24700);
const BASE = `https://127.0.0.1:${PORT}`;

async function waitHealthy(timeoutMs: number) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('panel did not become healthy');
}

export default async function globalSetup() {
  const data = mkdtempSync(join(tmpdir(), 'fp-e2e-'));
  const bin = join(process.cwd(), 'forgepanel-test');
  if (!existsSync(bin)) throw new Error('forgepanel-test binary missing — build it: go build -o e2e/forgepanel-test ./cmd/forgepanel');
  const env = {
    ...process.env,
    FORGEPANEL_DATA: data,
    FORGEPANEL_PANEL_PORT: String(PORT),
    FORGEPANEL_API_PORT: String(PORT + 1),
    FORGEPANEL_SUB_PORT: String(PORT + 2),
    FORGEPANEL_DNS_PORT: String(PORT + 3),
  };
  const proc = spawn(bin, [], { env, stdio: 'ignore', detached: true });
  proc.unref();
  writeFileSync('.panel.pid', String(proc.pid));
  writeFileSync('.paneldata', data);

  await waitHealthy(20_000);

  // Complete first-run setup using the token the panel wrote to disk.
  const token = readFileSync(join(data, 'setup-token.txt'), 'utf8').trim();
  const password = 'E2Epass!2345';
  const r = await fetch(`${BASE}/api/setup/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, username: 'admin', password, password_confirm: password }),
  });
  if (!r.ok) throw new Error('setup/init failed: ' + (await r.text()));
  writeFileSync('.auth.json', JSON.stringify({ baseURL: BASE, username: 'admin', password }));
}
