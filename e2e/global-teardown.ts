import { readFileSync, existsSync, rmSync } from 'node:fs';

export default async function globalTeardown() {
  try {
    if (existsSync('.panel.pid')) {
      const pid = Number(readFileSync('.panel.pid', 'utf8').trim());
      try { process.kill(-pid); } catch {}
      try { process.kill(pid); } catch {}
    }
    if (existsSync('.paneldata')) {
      const d = readFileSync('.paneldata', 'utf8').trim();
      rmSync(d, { recursive: true, force: true });
    }
  } catch {}
}
