package binmgr

import (
	"bytes"
	"io"
)

// bytesReader wraps a byte slice as an io.Reader.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// bytesReaderAt wraps a byte slice as an io.ReaderAt (for zip.NewReader).
func bytesReaderAt(b []byte) io.ReaderAt { return bytes.NewReader(b) }
