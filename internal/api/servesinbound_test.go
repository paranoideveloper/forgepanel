package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// The panel advertised SSH in its protocol list, minted a default credential for
// it, accepted the inbound, and then failed to render it on every reload. The
// inbound existed in the database and served nobody — sing-box has an SSH
// OUTBOUND and no SSH inbound, and no core here implements an SSH server.

func TestSSHIsNotOfferedAsAnInbound(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/protocols", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var protos []struct {
		Proto         string `json:"proto"`
		ServesInbound bool   `json:"serves_inbound"`
	}
	if err := json.Unmarshal([]byte(body), &protos); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range protos {
		if p.Proto == string(model.ProtoSSH) {
			found = true
			if p.ServesInbound {
				t.Error("SSH is advertised as servable as an inbound; no core here implements an SSH server")
			}
		} else if !p.ServesInbound {
			// Everything else must stay offered. Over-restricting here would
			// silently remove working protocols from the UI.
			t.Errorf("%s was marked as not servable", p.Proto)
		}
	}
	if !found {
		t.Fatal("SSH vanished from the protocol list entirely; it is still usable as an egress hop")
	}
}

func TestCreatingAnSSHInboundIsRefusedWithAReason(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/inbounds", token,
		`{"protocol":"ssh","address":"0.0.0.0","port":2222,"remark":"ssh-in"}`)
	if code == 200 || code == 201 {
		t.Fatalf("an SSH inbound was accepted (%d): it can never render, so it would sit in the database serving nobody", code)
	}
	// The refusal has to say what to do instead, or it reads as the panel being
	// broken rather than the protocol being outbound-only.
	if !strings.Contains(body, "egress") && !strings.Contains(body, "sshd") {
		t.Errorf("the refusal offers no alternative: %s", body)
	}
}

func TestServesInboundMatchesWhatTheRendererCanDo(t *testing.T) {
	// The list and the renderer must not drift. Every protocol the panel says it
	// serves must reach a real inbound case rather than the switch's default.
	for _, p := range model.AllProtocols() {
		if !render.ServesInbound(p) {
			continue
		}
		if render.EngineFor(p) != model.EngineSingBox {
			// xray, brook, amneziawg and forgedns have their own renderers; this
			// check is about the sing-box switch, which is where SSH fell
			// through.
			continue
		}
		n := &model.Node{Protocol: p, Address: "0.0.0.0", Port: 4443, Remark: "probe"}
		n.Normalize()
		_, err := render.SingboxInbound(n)
		if err != nil && strings.Contains(err.Error(), "has no sing-box inbound here") {
			t.Errorf("%s is advertised as servable but the renderer has no inbound case for it", p)
		}
	}
}
