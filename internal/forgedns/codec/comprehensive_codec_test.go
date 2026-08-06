package codec

import (
	"testing"
)

func TestCodec_SignVerifyAndHandshake(t *testing.T) {
	_, secret, err := NewSessionSecret()
	if err != nil || len(secret) == 0 {
		t.Fatalf("NewSessionSecret failed: %v", err)
	}

	frame := &Frame{
		SessionID: 100,
		Seq:       1,
		Flags:     FlagEXT,
		Payload:   []byte("hello forgepanel dns"),
		Ext:       &FrameExt{},
	}

	SignFrame(frame, secret)
	if !VerifyFrame(*frame, secret) {
		t.Fatalf("VerifyFrame failed for valid signature")
	}

	if VerifyFrame(*frame, []byte("wrong-secret-key-32-bytes-long!!")) {
		t.Fatalf("VerifyFrame succeeded for invalid secret")
	}

	// Handshake
	hsPayload := MakeHandshake(100, secret)
	hsFrame := Frame{
		SessionID: 100,
		Seq:       0,
		Flags:     FlagSYN | FlagACK,
		Payload:   hsPayload,
	}
	id, pub, err := ParseHandshake(hsFrame)
	if err != nil || id != 100 || len(pub) == 0 {
		t.Fatalf("ParseHandshake failed: id=%d, pubLen=%d, err=%v", id, len(pub), err)
	}
}
