import { describe, expect, test } from 'bun:test';
import { landingHTML } from '../src/panel/landing';
import { qrSvg } from '../src/panel/qr';

describe('end-user landing page', () => {
  const html = landingHTML('edge.example.workers.dev', 'securepath123456', 'usertok', 'ForgeEdge');
  const subUrl = 'https://edge.example.workers.dev/securepath123456/sub/usertok';

  test('embeds the subscriber-specific sub URL, never the admin path', () => {
    expect(html).toContain(subUrl);
    expect(html).not.toContain('/panel');
    expect(html).not.toContain('/api/');
  });

  test('offers one-tap import for the mainstream clients', () => {
    expect(html).toContain(`v2rayng://install-sub?url=${encodeURIComponent(subUrl)}`);
    expect(html).toContain(`streisand://import/${subUrl}`);
    expect(html).toContain(`sing-box://import-remote-profile?url=${encodeURIComponent(subUrl)}`);
    expect(html).toContain(`clash://install-config?url=${encodeURIComponent(subUrl)}`);
    expect(html).toContain(`shadowrocket://add/sub://${btoa(subUrl)}`);
  });

  test('links the direct per-format URLs', () => {
    for (const f of ['v2ray', 'clash', 'sing-box', 'xray']) {
      expect(html).toContain(`${subUrl}/${f}`);
    }
  });

  test('renders a self-contained SVG QR (no external requests)', () => {
    expect(html).toContain('<svg');
    expect(html).not.toMatch(/https?:\/\/[^"']*\.(png|js|css)/); // nothing fetched
  });

  test('qrSvg is deterministic and encodes the given text size sanely', () => {
    // A longer URL must not crash and must still be a single self-contained svg.
    const svg = qrSvg('https://a.very-long.example/forgeedge/securepath/sub/abcdef0123456789');
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('</svg>');
    expect(qrSvg('x')).toBe(qrSvg('x')); // deterministic
  });
});
