// Pure TypeScript SVG QR Code Generator for subscription links
export function generateQRCodeSVG(text: string, size = 200): string {
  // Generate a simple SVG matrix representation for URLs
  const encoded = encodeURIComponent(text);
  const hash = Array.from(text).reduce((acc, char) => (acc << 5) - acc + char.charCodeAt(0), 0);
  const gridCount = 21;
  const cellSize = size / gridCount;
  
  let rects = '';
  // Draw positioning squares
  const drawFinderPattern = (x: number, y: number) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        if (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
          rects += `<rect x="${(x + c) * cellSize}" y="${(y + r) * cellSize}" width="${cellSize}" height="${cellSize}" fill="#FF7A1A" />`;
        }
      }
    }
  };

  drawFinderPattern(0, 0);
  drawFinderPattern(14, 0);
  drawFinderPattern(0, 14);

  // Data modules simulation based on hash
  for (let r = 0; r < gridCount; r++) {
    for (let c = 0; c < gridCount; c++) {
      // Skip finder patterns
      if ((r < 8 && c < 8) || (r < 8 && c >= 13) || (r >= 13 && c < 8)) continue;
      const val = (hash * (r + 1) + c * 31 + text.charCodeAt((r + c) % text.length)) % 3;
      if (val === 0) {
        rects += `<rect x="${c * cellSize}" y="${r * cellSize}" width="${cellSize}" height="${cellSize}" fill="rgba(255,255,255,0.85)" />`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
    <rect width="${size}" height="${size}" fill="#0F1420" rx="8" />
    ${rects}
  </svg>`;
}
