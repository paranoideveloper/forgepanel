package edge

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// The Worker's scheduled() handler does the clean-IP refresh, the external-sub
// merge, the feed pull and the update check. The cron that fires it was
// declared only in wrangler.jsonc, and the panel never runs wrangler: it PUTs
// the prebuilt bundle straight at the API. So every panel-deployed Worker had a
// scheduled() handler nothing ever called, and nothing about the deploy said so.
func TestDeployRegistersTheCronTrigger(t *testing.T) {
	m := newCFMock(t)
	e := newEdgeStub(t)

	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none on a clean deploy", res.Warnings)
	}
	got := m.snapshot().Schedules["w"]
	if !reflect.DeepEqual(got, DefaultCrons) {
		t.Fatalf("registered crons = %v, want %v — the Worker's scheduled() handler would never fire", got, DefaultCrons)
	}

	// And the client can read them back, which is the only way an operator can
	// confirm the trigger without opening the Cloudflare dashboard.
	list, err := m.client().Schedules(ctx(t), "w")
	if err != nil {
		t.Fatalf("Schedules: %v", err)
	}
	if !reflect.DeepEqual(list, DefaultCrons) {
		t.Errorf("Schedules() = %v, want %v", list, DefaultCrons)
	}
}

// The heal path DELETES the script and uploads it again. Cloudflare keeps the
// schedules on the script, so they die with it: registering the cron before the
// probe would leave a healed Worker with no trigger at all.
func TestDeployRegistersTheCronTriggerAfterARecreate(t *testing.T) {
	m := newCFMock(t)
	e := newEdgeStub(t)
	e.throwUntilRecreate = 1
	m.OnDeleteScript = func(string) { e.noteRecreate() }

	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err != nil {
		t.Fatalf("Deploy did not recover a throwing Worker: %v", err)
	}
	if res.Health == nil || !res.Health.Recreated {
		t.Fatalf("health = %+v, want a recreate — this test is not exercising the heal path", res.Health)
	}
	got := m.snapshot().Schedules["w"]
	if !reflect.DeepEqual(got, DefaultCrons) {
		t.Fatalf("registered crons after the recreate = %v, want %v", got, DefaultCrons)
	}
}

// A trigger that could not be registered must not fail the deploy: the Worker
// is live and serving by then, and an error would send the operator hunting for
// something that is actually running. It must not be silent either — the
// periodic refresh is genuinely off.
func TestDeployWarnsWhenTheCronTriggerCannotBeRegistered(t *testing.T) {
	m := newCFMock(t)
	e := newEdgeStub(t)
	key := "PUT /accounts/acct-1/workers/scripts/w/schedules"
	m.Deny[key] = apiMessage{Code: 10000, Message: "Authentication error"}
	m.DenyStatus[key] = http.StatusForbidden

	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err != nil {
		t.Fatalf("a refused schedule registration failed the whole deploy: %v", err)
	}
	if res.Health == nil || !res.Health.OK {
		t.Fatalf("health = %+v, want the Worker reported healthy", res.Health)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "cron trigger") {
		t.Fatalf("warnings = %v, want one naming the cron trigger", res.Warnings)
	}
	if !strings.Contains(res.Warnings[0], DefaultCrons[0]) {
		t.Errorf("warning %q does not tell the operator which schedule to add by hand", res.Warnings[0])
	}
}

func TestPutSchedulesNeedsAnAccount(t *testing.T) {
	c := &Client{Token: "t"}
	err := c.PutSchedules(ctx(t), "w", DefaultCrons)
	e, ok := AsError(err)
	if !ok || e.Kind != KindValidation {
		t.Fatalf("err = %v, want a validation error about the missing account id", err)
	}
}
