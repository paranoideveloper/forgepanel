/**
 * QR codes for subscription links and share URIs.
 *
 * The previous implementation was not a QR encoder. It drew three finder
 * patterns and then filled the data area from a string hash:
 *
 *     const val = (hash * (r + 1) + c * 31 + text.charCodeAt((r + c) % text.length)) % 3;
 *
 * There was no encoding, no error correction, no format information and no
 * masking, and the grid was fixed at 21x21 regardless of how long the payload
 * was. The result LOOKS like a QR code — which is the whole problem. Scanning a
 * config from the panel is the primary way a user gets a VPN onto a phone, and
 * every one of those scans failed while the panel showed a perfectly plausible
 * image and reported nothing.
 *
 * It now uses Project Nayuki's encoder (MIT, vendored), the same one the
 * ForgeEdge Worker already used to produce scannable codes. Correctness is
 * verified by DECODING the output back to the input, not by looking at it.
 */
import { qrcodegen } from '$lib/vendor/qrcodegen';

/** Dark and light module colours, matching the panel's surface. */
const DARK = '#0F1420';
const LIGHT = '#FFFFFF';

/**
 * Build the module matrix for a payload.
 *
 * Exposed separately so tests can assert the modules themselves rather than the
 * SVG text around them: a golden comparison against an independent encoder is
 * what proves this is a real QR code.
 */
export function qrMatrix(text: string): boolean[][] {
  // MEDIUM recovers ~15% damage. It is the usual choice for links, and it keeps
  // the code small enough to stay scannable on a phone screen while tolerating
  // the glare and partial occlusion of scanning a monitor.
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const out: boolean[][] = [];
  for (let y = 0; y < qr.size; y++) {
    const row: boolean[] = [];
    for (let x = 0; x < qr.size; x++) row.push(qr.getModule(x, y));
    out.push(row);
  }
  return out;
}

/**
 * Render a payload as a self-contained SVG.
 *
 * `size` is the pixel width of the finished image; the module grid is sized by
 * the encoder from the payload length, so a long share URI produces a denser
 * code rather than an unscannable one crammed into 21x21.
 *
 * The quiet zone is not decoration: the spec requires four clear modules on
 * every side, and decoders genuinely fail without it. The old version had none.
 */
export function generateQRCodeSVG(text: string, size = 200): string {
  if (!text) {
    // An empty payload has nothing to encode. Returning a blank frame is honest;
    // encoding the empty string would produce a valid QR that scans to nothing,
    // which looks like a working code and wastes the user's time.
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="No data to encode"><rect width="${size}" height="${size}" fill="${LIGHT}" rx="8"/></svg>`;
  }

  const modules = qrMatrix(text);
  const border = 4; // required quiet zone
  const grid = modules.length + border * 2;

  // One path for every dark module beats one <rect> each: the same image at a
  // fraction of the DOM, which matters when a list renders a QR per row.
  let path = '';
  for (let y = 0; y < modules.length; y++) {
    for (let x = 0; x < modules.length; x++) {
      if (modules[y][x]) path += `M${x + border},${y + border}h1v1h-1z`;
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${grid} ${grid}" ` +
    `width="${size}" height="${size}" shape-rendering="crispEdges" ` +
    `role="img" aria-label="QR code">` +
    `<rect width="${grid}" height="${grid}" fill="${LIGHT}"/>` +
    `<path d="${path}" fill="${DARK}"/>` +
    `</svg>`
  );
}
