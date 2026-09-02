package api

import (
	"encoding/json"
	"testing"

	"github.com/forgepanel/forgepanel/internal/job"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// TestShadowTLSIdentityMatchesServedInbound pins the two halves of ShadowTLS
// authentication to the same secret.
//
// The served inbound emits one shadowtls user per assigned panel user, keyed on
// that user's password. stampIdentity had no ShadowTLS case, so the
// subscription handed out the INBOUND's template password instead. The
// camouflage handshake still completed — the inbound looked healthy, the port
// was open, sing-box logged nothing at startup — and every real connection then
// failed with:
//
//	shadow-tls v3: hmac mismatch
//
// Observed on a generated ShadowTLS preset before the fix.
func TestShadowTLSIdentityMatchesServedInbound(t *testing.T) {
	const userPW = "USER-OWN-PASSWORD"
	tmpl := &model.Node{
		Protocol: model.ProtoShadowTLS, Address: "203.0.113.9", Port: 8449,
		Password: "inner-ss-key",
		ShadowTLS: &model.ShadowTLSOptions{
			Version: 3, Password: "INBOUND-TEMPLATE-PASSWORD",
			HandshakeHost: "www.cloudflare.com", HandshakePort: 443,
			InnerMethod: "2022-blake3-aes-128-gcm",
		},
	}
	u := &store.User{Username: "alice", Password: userPW, Status: store.StatusActive}
	u.ID = 1

	// What the subscriber is handed.
	client := tmpl.Clone()
	stampIdentity(client, u)
	if client.ShadowTLS == nil {
		t.Fatal("stampIdentity dropped the ShadowTLS block")
	}
	if client.ShadowTLS.Password != userPW {
		t.Errorf("client got %q, want the user's own password %q",
			client.ShadowTLS.Password, userPW)
	}

	// What the server is told to accept.
	served := serverShadowTLSPasswords(t, tmpl, u)
	if len(served) == 0 {
		t.Fatal("the served inbound accepts no shadowtls user at all")
	}
	var match bool
	for _, pw := range served {
		if pw == client.ShadowTLS.Password {
			match = true
		}
	}
	if !match {
		t.Errorf("the served inbound accepts %v, but the subscription hands out %q — "+
			"this is the hmac mismatch", served, client.ShadowTLS.Password)
	}
}

// serverShadowTLSPasswords renders the inbound the engine actually serves and
// returns the passwords it will accept.
func serverShadowTLSPasswords(t *testing.T, n *model.Node, users ...*store.User) []string {
	t.Helper()
	clients := make([]engine.ClientCred, 0, len(users))
	for _, u := range users {
		clients = append(clients, engine.ClientCred{
			Email: job.UserEmail(u.ID), Username: u.Username, UUID: u.UUID, Password: u.Password,
		})
	}
	b, err := engine.BuildMulti([]engine.InboundSpec{{Node: n, Clients: clients}}, 0, "", "")
	if err != nil {
		t.Fatalf("engine.BuildMulti: %v", err)
	}
	var doc struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(b.Singbox, &doc); err != nil {
		t.Fatalf("sing-box config is not JSON: %v", err)
	}
	var out []string
	for _, in := range doc.Inbounds {
		if in["type"] != "shadowtls" {
			continue
		}
		arr, _ := in["users"].([]any)
		for _, e := range arr {
			if m, ok := e.(map[string]any); ok {
				if pw, ok := m["password"].(string); ok {
					out = append(out, pw)
				}
			}
		}
	}
	return out
}
