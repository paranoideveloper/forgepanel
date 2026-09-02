package api

import (
	"encoding/json"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The inbound list builds its rows as a hand-written map rather than marshalling
// the stored row, so a field can be added to the model, written by the panel and
// read by the UI while never once crossing the wire.
//
// Two did. NotServingReason — the whole "this inbound is enabled and is NOT in
// the running config" mechanism, with a detector, a stored reason, a "since"
// timestamp and an audit entry on every transition — was absent from the payload,
// so the badge the table renders for it could not appear and an inbound carrying
// no traffic displayed as Enabled with nothing anywhere saying why. PrevNodeJSON
// likewise: every edit writes it, the undo endpoint restores it, and the list
// gave the UI no way to know whether there was anything to undo.
func TestTheInboundListTellsTheUIWhatItNeedsToRender(t *testing.T) {
	s, token := adminAPI(t)

	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "127.0.0.1", Port: 34871,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "listed",
	}
	n.Normalize()
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	// The exact state the detector leaves behind: enabled, with a reason.
	if err := s.db.UpdateInboundFields(in.ID, map[string]any{
		"not_serving_reason": "no core in this panel can serve it",
	}); err != nil {
		t.Fatal(err)
	}
	in2, err := s.db.InboundByID(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	in2.PrevNodeJSON = in2.NodeJSON
	if err := s.db.SaveInbound(in2); err != nil {
		t.Fatal(err)
	}

	code, body := doGET(t, s, "/api/admin/inbounds", token)
	if code != 200 {
		t.Fatalf("listing inbounds returned %d: %s", code, body)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	for _, r := range rows {
		if r["remark"] == "listed" {
			row = r
		}
	}
	if row == nil {
		t.Fatalf("the inbound is not in the list: %s", body)
	}
	if got, _ := row["not_serving_reason"].(string); got != "no core in this panel can serve it" {
		t.Errorf("not_serving_reason = %q; the badge in the table can never render without it", got)
	}
	if got, _ := row["can_undo"].(bool); !got {
		t.Errorf("can_undo = %v, but this inbound has a previous config the undo endpoint would restore", row["can_undo"])
	}
}

// And the negative: an inbound that was never edited must not offer undo, or the
// only way to discover there is nothing to restore is to press the button and
// read a 409.
func TestAFreshInboundReportsNothingToUndo(t *testing.T) {
	s, token := adminAPI(t)
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "127.0.0.1", Port: 34872,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "never-edited",
	}
	n.Normalize()
	if _, err := s.db.CreateInbound(n); err != nil {
		t.Fatal(err)
	}
	_, body := doGET(t, s, "/api/admin/inbounds", token)
	var rows []map[string]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r["remark"] != "never-edited" {
			continue
		}
		if got, _ := r["can_undo"].(bool); got {
			t.Errorf("can_undo = true for an inbound that was never edited")
		}
		if got, ok := r["not_serving_reason"].(string); ok && got != "" {
			t.Errorf("not_serving_reason = %q for a healthy inbound", got)
		}
	}
}

var _ = store.Inbound{}
