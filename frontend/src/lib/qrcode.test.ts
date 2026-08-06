import { describe, it, expect } from 'vitest';
import { generateQRCodeSVG } from './qrcode';

describe('QRCode SVG Generator', () => {
  it('generates valid SVG string for subscription URL', () => {
    const svg = generateQRCodeSVG('https://example.com/sub/token123', 200);
    expect(svg).toContain('<svg');
    expect(svg).toContain('viewBox="0 0 200 200"');
    expect(svg).toContain('#FF7A1A');
    expect(svg).toContain('</svg>');
  });
});
