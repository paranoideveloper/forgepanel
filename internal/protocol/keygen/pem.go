package keygen

import (
	"bytes"
	"encoding/pem"
)

// encodePEM wraps DER bytes in a PEM block of the given type.
func encodePEM(der []byte, typ string) []byte {
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: typ, Bytes: der})
	return buf.Bytes()
}
