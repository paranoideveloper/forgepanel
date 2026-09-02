#!/usr/bin/env python3
"""Verify the panel's QR codes actually scan.

The panel's previous QR "encoder" drew three finder patterns and filled the data
area from a string hash. It looked like a QR code and decoded to nothing, so
every scan-to-import failed while the panel appeared to work. A unit test cannot
catch that on its own: the only property that matters is whether a decoder can
read the symbol back.

This renders the committed golden matrices (frontend/src/lib/qrcode.golden.json,
produced by the panel's own encoder) to images and decodes them with an
independent decoder, asserting an exact round trip.

    python3 tools/qrverify/verify_qr.py

Requires numpy and opencv-python. Exits non-zero if any symbol fails to decode
back to its input.
"""
import json
import pathlib
import sys

try:
    import cv2
    import numpy as np
except ImportError:
    print("verify_qr: needs numpy and opencv-python (pip install numpy opencv-python-headless)")
    sys.exit(2)

GOLDEN = pathlib.Path(__file__).resolve().parents[2] / "frontend/src/lib/qrcode.golden.json"
BORDER = 4   # the quiet zone the spec requires; decoders genuinely fail without it
SCALE = 10   # pixels per module


def render(rows, n):
    dim = (n + BORDER * 2) * SCALE
    img = np.full((dim, dim), 255, dtype=np.uint8)
    for y in range(n):
        for x in range(n):
            if rows[y][x] == "1":
                y0, x0 = (y + BORDER) * SCALE, (x + BORDER) * SCALE
                img[y0:y0 + SCALE, x0:x0 + SCALE] = 0
    return img


def main():
    data = json.loads(GOLDEN.read_text())
    detector = cv2.QRCodeDetector()
    failures = 0
    for text, v in data.items():
        got, _, _ = detector.detectAndDecode(render(v["rows"], v["size"]))
        ok = got == text
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  modules={v['size']:3d}  {text[:60]!r}")
        if not ok:
            print(f"      decoded {got[:100]!r}")
    if failures:
        print(f"\n{failures} symbol(s) do not scan.")
        return 1
    print(f"\nAll {len(data)} symbols decode back to their input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
