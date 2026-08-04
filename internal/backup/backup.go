// Package backup implements encrypted backup and restore (spec §12): it packs the
// panel's SQLite database (and any extra files) into a tar, encrypts it with
// AES-256-GCM under a key derived from the panel master secret, and can restore
// it with one call. Destinations (local/S3/Telegram) layer on top of the raw
// Create/Restore bytes.
package backup

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// magic prefixes an encrypted backup so restore can sanity-check it.
var magic = []byte("FPBK1")

// deriveKey turns an arbitrary master secret into a 32-byte AES key.
func deriveKey(master string) []byte {
	sum := sha256.Sum256([]byte("forgepanel-backup:" + master))
	return sum[:]
}

// Create packs the named files (relative names preserved as their base name) into
// an encrypted blob. Missing files are skipped so a partial data dir still backs
// up cleanly.
func Create(master string, files []string) ([]byte, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	included := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // skip absent files
		}
		hdr := &tar.Header{Name: filepath.Base(f), Mode: 0o600, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
		included++
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if included == 0 {
		return nil, errors.New("backup: nothing to back up")
	}
	return encrypt(deriveKey(master), tarBuf.Bytes())
}

// Restore decrypts a blob and writes each contained file into destDir.
func Restore(master string, blob []byte, destDir string) ([]string, error) {
	plain, err := decrypt(deriveKey(master), blob)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	var restored []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(destDir, filepath.Base(hdr.Name))
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, err
		}
		restored = append(restored, dst)
	}
	return restored, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, magic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, magic), nil
}

func decrypt(key, blob []byte) ([]byte, error) {
	if len(blob) < len(magic) || !bytes.Equal(blob[:len(magic)], magic) {
		return nil, errors.New("backup: not a ForgePanel backup (bad magic)")
	}
	blob = blob[len(magic):]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("backup: truncated")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, magic)
}
