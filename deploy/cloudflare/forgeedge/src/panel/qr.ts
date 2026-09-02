/**
 * A QR of the subscription URL for the landing page. Uses Project Nayuki's
 * QR encoder (vendored, MIT) so the output is correct and scannable — verified
 * by decoding it back to the URL, not by eyeballing it.
 */
import { qrcodegen } from '../vendor/qrcodegen';

/** Minimal SVG QR (no external deps), dark modules on a transparent ground. */
export function qrSvg(text: string, border = 2): string {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const size = qr.size + border * 2;
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="220" height="220" role="img" aria-label="Subscription QR"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}
