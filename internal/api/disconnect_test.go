package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/online"
	"github.com/forgepanel/forgepanel/internal/job"
)

func credentialIn(s *Server, email string) bool {
	for _, sp := range s.enabledInboundSpecs() {
		for _, cl := range sp.Clients {
			if cl.Email == email {
				return true
			}
		}
	}
	return false
}

// Disconnecting holds the user out of the cores — which is what refuses the
// client's immediate reconnect — and reconnecting lifts the hold early.
func TestDisconnectHoldsTheUserOutAndReconnectLetsThemBack(t *testing.T) {
	f := newUGFixture(t)
	f.router.POST("/api/admin/users/:id/disconnect", f.s.signer.Middleware(), f.s.handleDisconnectUser)
	f.router.POST("/api/admin/users/:id/reconnect", f.s.signer.Middleware(), f.s.handleReconnectUser)
	email := job.UserEmail(f.user.ID)
	path := "/api/admin/users/" + itoaU(f.user.ID)

	if !credentialIn(f.s, email) {
		t.Fatal("precondition: the active user should be in the core config")
	}
	rec := f.do(t, http.MethodPost, path+"/disconnect", f.ownerTok, `{"hold_seconds":600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disconnect: %d %s", rec.Code, rec.Body.String())
	}
	var res disconnectResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(res.HeldUntil); d < 590*time.Second || d > 601*time.Second {
		t.Fatalf("held for %v, want about 10 minutes", d)
	}
	if credentialIn(f.s, email) {
		t.Fatal("a disconnected user is still in the core config, so the client just reconnects")
	}

	if rec := f.do(t, http.MethodPost, path+"/reconnect", f.ownerTok, ""); rec.Code != http.StatusOK {
		t.Fatalf("reconnect: %d %s", rec.Code, rec.Body.String())
	}
	if !credentialIn(f.s, email) {
		t.Fatal("reconnect did not put the user back")
	}
}

// A reseller cannot disconnect a user they do not own.
func TestAResellerCannotDisconnectSomeoneElsesUser(t *testing.T) {
	f := newUGFixture(t)
	f.router.POST("/api/admin/users/:id/disconnect", f.s.signer.Middleware(), f.s.handleDisconnectUser)
	rec := f.do(t, http.MethodPost, "/api/admin/users/"+itoaU(f.user.ID)+"/disconnect", f.resellerTok, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reseller got %d, want 404", rec.Code)
	}
}

// An address another online user also connects from is never closed: behind a
// CDN or carrier NAT it belongs to many people.
func TestSharedAddressesAreNotTargeted(t *testing.T) {
	presence := []online.Presence{
		{User: "u1", Sessions: []online.Session{{IP: "198.51.100.1"}, {IP: "198.51.100.9"}}},
		{User: "u2", Sessions: []online.Session{{IP: "198.51.100.9"}}},
	}
	mine, shared := sessionAddresses(presence, "u1")
	if len(mine) != 2 || !shared["198.51.100.9"] || shared["198.51.100.1"] {
		t.Fatalf("mine=%v shared=%v", mine, shared)
	}
}
