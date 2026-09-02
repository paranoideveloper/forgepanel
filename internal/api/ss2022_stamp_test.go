package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// TestStampIdentityShadowsocks2022 pins the subscription-facing half of per-user
// SS-2022: a user's stamped node must carry "serverPSK:userPSK" (a valid two-
// segment EIH password whose user segment is the deterministic per-user PSK the
// engine also materializes), while a non-2022 method keeps the single shared key.
func TestStampIdentityShadowsocks2022(t *testing.T) {
	u := &store.User{Status: store.StatusActive}
	u.ID = 7
	const serverPSK = "GdBYbY0M9WQ7l3z8i5oQ2g==" // 16 bytes, aes-128 sized

	// SS-2022: combined password, user segment == the engine's derivation.
	n := &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SS2022AES128, Password: serverPSK,
		Address: "example.com", Port: 8388}
	stampIdentity(n, u)
	wantUser := model.DeriveSSUserPSK(job.UserEmail(u.ID), model.SS2022AES128)
	if n.Password != serverPSK+":"+wantUser {
		t.Fatalf("SS-2022 stamp = %q, want %q", n.Password, serverPSK+":"+wantUser)
	}
	// The combined password must be a structurally valid SS-2022 credential.
	if err := n.Validate(); err != nil {
		t.Fatalf("stamped SS-2022 node does not validate: %v", err)
	}

	// Non-2022: the shared key is preserved (no per-user identity header).
	shared := &model.Node{Protocol: model.ProtoShadowsocks, Method: model.SSAES256GCM, Password: "sharedkey"}
	stampIdentity(shared, u)
	if shared.Password != "sharedkey" {
		t.Fatalf("non-2022 SS must keep the shared key, got %q", shared.Password)
	}
}
