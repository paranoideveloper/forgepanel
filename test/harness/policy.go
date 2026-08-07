//go:build harness

// policy.go proves the negative half of the contract. A panel that carries
// traffic is only half-correct; it also has to STOP carrying it when an account
// expires, exhausts its quota, is disabled, presents the wrong credential, or
// loses the inbound. Each case here first establishes that the tunnel works, so
// a later refusal cannot be confused with a tunnel that never worked.
package harness

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// RunPolicy executes one enforcement case.
func (r *Runner) RunPolicy(c Case) Result {
	start := time.Now()
	res := Result{Case: c, Engine: c.Engine(), Status: StatusFail}
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()

	port := r.nextPort
	r.nextPort++
	socks := r.nextSock
	r.nextSock += 2
	res.Port = port

	step := func(name string, err error, note string) bool {
		s := Step{Name: name, OK: err == nil, Note: note}
		if err != nil {
			s.Error = err.Error()
		}
		res.Steps = append(res.Steps, s)
		return err == nil
	}

	in, err := r.Panel.CreateInbound(c.InboundPayload(port, r.Env.RealityDest))
	if !step("create-inbound", err, fmt.Sprintf("port %d", port)) {
		res.Reason = "create inbound: " + err.Error()
		return res
	}
	inboundAlive := true
	defer func() {
		if inboundAlive {
			_ = r.Panel.DeleteInbound(in.ID)
		}
	}()
	user, err := r.Panel.CreateUser("p-" + sanitize(c.Policy))
	if !step("create-user", err, "") {
		res.Reason = "create user: " + err.Error()
		return res
	}
	defer func() { _ = r.Panel.DeleteUser(user.ID) }()
	if !step("assign-inbound", r.Panel.SetUserInbounds(user.ID, []uint{in.ID}), "") {
		res.Reason = "assign inbound"
		return res
	}

	listen := fmt.Sprintf("%s:%d", hostOf(r.Env.PanelURL), port)
	if err := waitPort(listen, 25*time.Second); err != nil {
		res.Reason = "inbound never listened on " + listen
		step("inbound-listening", err, listen)
		return res
	}

	// The unknown-token case never gets as far as a client: the proof is that
	// the subscription endpoint hands out nothing usable.
	if c.Policy == "sub-token-unknown" {
		raw, _, err := r.Panel.Subscription("thistokendoesnotexistatall", "xray", "v2rayNG")
		if err != nil {
			res.Status = StatusPass
			res.Reason = "unknown token rejected: " + err.Error()
			step("unknown-token", nil, err.Error())
			return res
		}
		if _, perr := FromXraySubscription(raw, socks); perr != nil {
			res.Status = StatusPass
			res.Reason = "unknown token yielded an empty subscription (" + perr.Error() + ")"
			step("unknown-token", nil, res.Reason)
			return res
		}
		res.Status = StatusFail
		res.Reason = "an unknown subscription token produced a runnable client config"
		step("unknown-token", errors.New(res.Reason), "")
		return res
	}

	// --- baseline: the tunnel must work before we try to break it ---------
	raw, _, err := r.Panel.Subscription(user.SubToken, "xray", "v2rayNG/1.8.0")
	if !step("fetch-subscription", err, "") {
		res.Reason = "fetch subscription: " + err.Error()
		return res
	}
	cfg, err := FromXraySubscription(raw, socks)
	if !step("parse-client-config", err, "") {
		res.Reason = err.Error()
		return res
	}
	logDir := filepath.Join(r.Env.ResultsDir, "logs")
	core, err := Launch(r.mustCore("xray"), cfg, logDir, sanitize(c.ID), 20*time.Second)
	if !step("launch-client", err, "") {
		res.Reason = "client core would not run the emitted config: " + err.Error()
		return res
	}
	defer core.Stop()
	res.Mutations = cfg.Mutations
	res.Artifacts = append(res.Artifacts, r.save(c.ID+".client.json", cfg.JSON), core.LogPath())

	seed := time.Now().UnixNano()
	base := r.probeWithRetry(core.Addr(), seed)
	res.TCP = &base
	if !step("baseline-allowed", errFrom(base.OK, base.Error), fmt.Sprintf("%d bytes", base.Bytes)) {
		res.Reason = "baseline tunnel never worked, so the denial cannot be attributed: " + base.Error
		return res
	}

	// --- apply the rule ----------------------------------------------------
	settle := 12 * time.Second
	switch c.Policy {
	case "user-disabled":
		if !step("disable-user", r.Panel.PatchUser(user.ID, map[string]any{"status": "disabled"}), "") {
			res.Reason = "could not disable the user"
			return res
		}
	case "user-expired":
		past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		if !step("expire-user", r.Panel.PatchUser(user.ID, map[string]any{"expire_at": past}), past) {
			res.Reason = "could not set expiry"
			return res
		}
		// Expiry is applied by the sweep, which runs on its own minute ticker.
		settle = 95 * time.Second
		step("await-sweep", r.waitStatus(user.ID, "expired", settle), "status must become expired")
	case "user-over-quota":
		limit := int64(PayloadSize / 2)
		if !step("set-quota", r.Panel.PatchUser(user.ID, map[string]any{"data_limit": limit}),
			fmt.Sprintf("%d bytes", limit)) {
			res.Reason = "could not set a data limit"
			return res
		}
		// Push more than the limit, then wait for the traffic poller to notice.
		_ = r.probeWithRetry(core.Addr(), seed+1)
		_ = r.probeWithRetry(core.Addr(), seed+2)
		settle = 45 * time.Second
		step("await-limit", r.waitStatus(user.ID, "limited", settle), "status must become limited")
	case "inbound-disabled":
		// store.Inbound has an Enabled column, ListInbounds reports it, and both
		// enabledInboundSpecs and subscriptionNodes honour it — but no route sets
		// it. Try the update endpoint anyway (with the node it stored, plus the
		// flag) so the result records what the API actually does, rather than an
		// assertion made from reading the router.
		node, nerr := r.Panel.InboundNode(in.ID)
		if nerr != nil {
			res.Reason = "could not read the inbound back: " + nerr.Error()
			return res
		}
		node["enabled"] = false
		uerr := r.Panel.UpdateInbound(in.ID, node)
		step("attempt-disable", uerr, "PUT /api/admin/inbounds/:id with enabled=false")
		time.Sleep(12 * time.Second)
		rows, _ := r.Panel.ListInbounds()
		stillEnabled := false
		for _, row := range rows {
			if row.ID == in.ID && row.Enabled {
				stillEnabled = true
			}
		}
		if stillEnabled {
			step("disable-took-effect", errors.New("inbound still reports enabled=true"), "")
			res.Status = StatusFail
			res.Reason = "the panel exposes no way to disable an inbound: store.Inbound.Enabled is set " +
				"true by store.CreateInbound and no handler ever clears it, and model.Node — the only body " +
				"PUT /api/admin/inbounds/:id accepts — has no such field. The only way to stop an inbound " +
				"serving is to delete it, which also destroys its configuration"
			return res
		}
	case "inbound-removed":
		if !step("delete-inbound", r.Panel.DeleteInbound(in.ID), "") {
			res.Reason = "could not delete the inbound"
			return res
		}
		inboundAlive = false
	case "wrong-credential":
		core.Stop()
		if !step("tamper-credential", cfg.Tamper(), "") {
			res.Reason = "could not tamper the credential"
			return res
		}
		res.Mutations = cfg.Mutations
		c2, lerr := Launch(r.mustCore("xray"), cfg, logDir, sanitize(c.ID)+".tampered", 20*time.Second)
		if !step("relaunch-tampered", lerr, "") {
			res.Reason = "tampered config would not start: " + lerr.Error()
			return res
		}
		core = c2
		defer core.Stop()
		settle = 0
	default:
		res.Reason = "unknown policy " + c.Policy
		return res
	}
	if settle > 0 && c.Policy != "user-expired" && c.Policy != "user-over-quota" {
		time.Sleep(settle)
	}

	// --- the tunnel must now refuse ---------------------------------------
	denied, detail := r.probeMustFail(core.Addr(), seed+9, 4)
	step("denied-after-rule", errFrom(denied, "traffic still flowed: "+detail), detail)
	if denied {
		res.Status = StatusPass
		res.Reason = "denied as required (" + detail + ")"
		return res
	}
	u, _ := r.Panel.GetUser(user.ID)
	statusNow := ""
	if u != nil {
		statusNow = u.Status
	}
	res.Status = StatusFail
	res.Reason = fmt.Sprintf("the tunnel kept carrying traffic after %s (user status=%q): %s",
		c.Policy, statusNow, detail)
	return res
}

// probeMustFail retries so a single transient success or failure cannot decide
// the verdict: the rule has to hold across consecutive attempts.
func (r *Runner) probeMustFail(socksAddr string, seed int64, attempts int) (bool, string) {
	var last string
	for i := 0; i < attempts; i++ {
		res := ProbeHTTP(socksAddr, r.Env.Origin, seed+int64(i), 10*time.Second)
		if res.OK {
			return false, fmt.Sprintf("attempt %d transferred %d bytes intact", i+1, res.Bytes)
		}
		last = res.Error
		time.Sleep(2 * time.Second)
	}
	return true, last
}

// waitStatus blocks until the panel reports the wanted user status.
func (r *Runner) waitStatus(userID uint, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	last := ""
	for time.Now().Before(deadline) {
		u, err := r.Panel.GetUser(userID)
		if err == nil {
			last = u.Status
			if u.Status == want {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("user status stayed %q, never became %q within %s", last, want, budget)
}
