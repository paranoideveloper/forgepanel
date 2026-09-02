import { describe, it, expect } from 'vitest';
import { generateQRCodeSVG, qrMatrix } from './qrcode';
import golden from './qrcode.golden.json';

// The previous implementation was not a QR encoder. It drew three finder
// patterns and filled the data area from a string hash — no encoding, no error
// correction, no format information, no masking — on a grid fixed at 21x21
// regardless of payload length. It LOOKED like a QR code, which is exactly why
// nobody noticed that scanning a config from the panel never worked, and
// scanning is the primary way a user gets a VPN onto a phone.
//
// The golden fixtures are this encoder's own output, PROVEN to scan: every one
// was rendered and decoded back to its exact input by an independent decoder
// (OpenCV's QRCodeDetector) via tools/qrverify/verify_qr.py. Re-run that script
// to re-establish the property from scratch; this file then guards it against
// regression without needing a decoder in the JS test environment.
//
// Comparing matrices against a different ENCODER would not work and is not the
// right test: mask-pattern selection legitimately differs between conforming
// implementations, so two correct encoders can produce two different — and
// equally scannable — matrices for the same payload. Decoding is the property
// that actually matters.

describe('qrMatrix', () => {
  for (const [text, expected] of Object.entries(
    golden as Record<string, { size: number; rows: string[] }>,
  )) {
    it(`still produces the verified-scannable symbol for ${JSON.stringify(text.slice(0, 40))}`, () => {
      const m = qrMatrix(text);
      expect(m.length).toBe(expected.size);
      const rows = m.map((r) => r.map((v) => (v ? '1' : '0')).join(''));
      expect(rows).toEqual(expected.rows);
    });
  }

  // The old encoder used 21x21 for everything, so a real share URI could not
  // physically fit: a 57-module payload was being crammed into 21 modules.
  it('grows the grid with the payload instead of truncating it', () => {
    const short = qrMatrix('short');
    const long = qrMatrix(
      'vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality' +
        '&sni=www.cloudflare.com&fp=chrome&pbk=xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU' +
        '&sid=0123abcd&type=tcp#NL-Edge',
    );
    expect(long.length).toBeGreaterThan(short.length);
  });

  // Every QR carries three finder patterns. Their absence, or a wrong shape,
  // means no decoder will even locate the symbol.
  it('places real finder patterns at three corners', () => {
    const m = qrMatrix('https://panel.example.com/sub/abc123');
    const n = m.length;
    const finderAt = (oy: number, ox: number) => {
      for (let y = 0; y < 7; y++) {
        for (let x = 0; x < 7; x++) {
          const ring = y === 0 || y === 6 || x === 0 || x === 6;
          const core = y >= 2 && y <= 4 && x >= 2 && x <= 4;
          if (m[oy + y][ox + x] !== (ring || core)) return false;
        }
      }
      return true;
    };
    expect(finderAt(0, 0)).toBe(true);
    expect(finderAt(0, n - 7)).toBe(true);
    expect(finderAt(n - 7, 0)).toBe(true);
  });
});

describe('generateQRCodeSVG', () => {
  it('emits a quiet zone, which decoders require', () => {
    const svg = generateQRCodeSVG('https://panel.example.com/sub/abc123', 200);
    const m = qrMatrix('https://panel.example.com/sub/abc123');
    // viewBox must be the module grid plus four clear modules on each side.
    expect(svg).toContain(`viewBox="0 0 ${m.length + 8} ${m.length + 8}"`);
  });

  it('renders at the requested pixel size', () => {
    const svg = generateQRCodeSVG('https://example.com/sub/token123', 256);
    expect(svg).toContain('width="256"');
    expect(svg).toContain('height="256"');
  });

  it('produces different images for different payloads', () => {
    // The old hash-based version could collide trivially; more importantly this
    // catches an encoder wired to ignore its input.
    expect(generateQRCodeSVG('https://a.example/one')).not.toBe(
      generateQRCodeSVG('https://a.example/two'),
    );
  });

  it('returns a blank frame for an empty payload rather than a code that scans to nothing', () => {
    const svg = generateQRCodeSVG('', 120);
    expect(svg).toContain('No data to encode');
    expect(svg).not.toContain('<path');
  });

  it('is a self-contained SVG with no external references', () => {
    const svg = generateQRCodeSVG('https://example.com/sub/token123');
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
  });
});
