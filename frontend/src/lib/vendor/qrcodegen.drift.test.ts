import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// The panel frontend and the ForgeEdge Worker are separate build roots with no
// shared module path, so Project Nayuki's encoder is vendored twice. Two copies
// of the same file drift: a fix lands in one and the other keeps producing the
// old output, and nothing reports it because both still "work". Cheaper to
// assert they are identical than to debug why a QR scans on the landing page and
// not in the panel.
describe('vendored QR encoder', () => {
  it('is byte-identical to the Worker copy', () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const panel = resolve(here, 'qrcodegen.ts');
    const worker = resolve(here, '../../../../deploy/cloudflare/forgeedge/src/vendor/qrcodegen.ts');
    expect(readFileSync(panel, 'utf8')).toBe(readFileSync(worker, 'utf8'));
  });

  it('keeps the MIT notice the licence requires', () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(resolve(here, 'qrcodegen.ts'), 'utf8');
    expect(src).toContain('Project Nayuki');
    expect(src).toContain('MIT License');
  });
});
