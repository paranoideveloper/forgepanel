package edge

import (
	"context"
	"strings"
)

// Deploy and Destroy are the whole-Worker lifecycle operations shared by the
// panel handlers and `forgectl edge`. Steps follow
// deploy/cloudflare/forgeedge/docs/FORGECTL_EDGE_SPEC.md.

// DeploySpec is one deploy or update.
type DeploySpec struct {
	Name   string
	Target string // workers (default) | pages
	// SecurePath is passed in as a plain-text binding rather than scraped back
	// out of a Worker log line, so forgectl knows every URL up front.
	SecurePath string
	// FeedPushToken is injected as a binding so the panel knows the Worker's
	// machine credential up front — the token that authorises pushing the feed
	// and the machine-driven WARP actions. Generated when empty. Ignored by a
	// Worker that already bootstrapped its secrets in KV (an update reuses them).
	FeedPushToken string
	Bundle        []byte
	// Domain attaches a custom hostname; the zone must be in this account.
	Domain string
	// Force overwrites a Worker that already exists. Silently overwriting
	// someone else's Worker is not acceptable, so this is never the default.
	Force bool
	// D1 also creates a D1 database and binds it.
	D1 bool
	// Update marks a re-upload of an existing Worker: the name check is skipped
	// and the existing KV namespace is reused rather than created.
	Update bool
	// SkipVerify returns as soon as the upload is accepted, without checking
	// that the Worker actually answers.
	//
	// Off by default, because "the API accepted the upload" and "the Worker
	// serves" are not the same thing, and the gap between them is what hands
	// somebody a dead panel link. Set it only where a probe is impossible —
	// an air-gapped test, or a deploy from a host with no route to the edge.
	SkipVerify bool
	// SelfManage binds this account's Cloudflare credential into the Worker
	// (CF_ACCOUNT_ID + CF_API_TOKEN), which is the only thing that lights up the
	// Worker's own Deployment panel — its script name, its workers.dev hostname
	// and any custom ones.
	//
	// Off by default and never implied. A token written INTO a Worker is
	// readable by anyone who can deploy to that account, so the operator has to
	// ask for it and has to be told what it costs — see the credential policy at
	// the head of cmd/forgectl/edge.go, and FORGECTL_EDGE_SPEC.md's
	// "--api-token — the fallback".
	SelfManage bool
	// Verify overrides the probe's timing. Zero values take the defaults.
	Verify VerifyOptions
}

// DeployResult is what an operator needs after a successful deploy.
type DeployResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Origin        string `json:"origin"`
	SecurePath    string `json:"secure_path"`
	FeedPushToken string `json:"feed_push_token,omitempty"`
	PanelURL      string `json:"panel_url"`
	SubTemplate   string `json:"subscription_template"`
	DoHURL        string `json:"doh_url"`
	// Health is the post-deploy probe: proof the Worker actually answers before
	// its URLs are handed to anyone. nil when verification was skipped.
	Health        *Health `json:"health,omitempty"`
	KVNamespaceID string  `json:"kv_namespace_id,omitempty"`
	D1DatabaseID  string  `json:"d1_database_id,omitempty"`
	Hostname      string  `json:"hostname,omitempty"`
	Updated       bool    `json:"updated"`
	// SelfManage echoes the spec, so a caller that registers the deployment
	// afterwards can persist the flag without being handed the spec as well.
	SelfManage bool `json:"self_manage"`
	// Warnings carry things that did not take even though the Worker itself
	// deployed. Failing the whole request for these would send an operator
	// hunting for something that is actually running; swallowing them would let
	// a setting they chose be silently ignored.
	Warnings []string `json:"warnings,omitempty"`
}

// Deploy uploads the Worker, wires its KV namespace, publishes it on
// workers.dev and optionally attaches a custom domain.
func Deploy(ctx context.Context, c *Client, spec DeploySpec) (*DeployResult, error) {
	if spec.Target == "" {
		spec.Target = "workers"
	}
	if spec.Target != "workers" {
		return nil, &Error{Op: "edge-deploy", Kind: KindValidation,
			Message: "only the workers target is implemented",
			Remediation: "deploy to Workers (the default). A Pages deployment uploads the same bundle as _worker.js; " +
				"it is not wired here because nothing has been able to exercise it end to end."}
	}
	if err := c.requireAccount("edge-deploy"); err != nil {
		return nil, err
	}
	if spec.SecurePath == "" {
		p, err := GenerateSecurePath(SecurePathLength)
		if err != nil {
			return nil, err
		}
		spec.SecurePath = p
	}
	if spec.FeedPushToken == "" {
		t, err := GenerateSecurePath(28)
		if err != nil {
			return nil, err
		}
		spec.FeedPushToken = t
	}

	// 2. Refuse to clobber an existing Worker.
	if !spec.Update {
		exists, err := c.ScriptExists(ctx, spec.Name)
		if err != nil {
			return nil, err
		}
		if exists && !spec.Force {
			return nil, &Error{Op: "edge-deploy", Kind: KindConflict,
				Message:     "a Worker named " + spec.Name + " already exists in this account",
				Remediation: "choose another --name, or pass --force to overwrite it deliberately."}
		}
	}

	// 3. KV: reuse the existing namespace on an update, create it otherwise.
	title := KVTitle(spec.Name)
	var kvID string
	if ns, err := c.FindKVNamespace(ctx, title); err == nil {
		kvID = ns.ID
	} else if IsNotFound(err) {
		ns, cerr := c.CreateKVNamespace(ctx, title)
		if cerr != nil {
			return nil, cerr
		}
		kvID = ns.ID
	} else {
		return nil, err
	}

	bindings := []Binding{
		KVBinding(kvID),
		// The Worker validates SECURE_PATH against ^[a-z0-9-]{8,64}$ and adopts
		// it instead of minting its own.
		PlainTextBinding("SECURE_PATH", spec.SecurePath),
		// The machine credential, so the panel can push the feed and drive WARP
		// without a browser session. Only adopted on first bootstrap; a Worker
		// whose secrets already live in KV keeps the token it minted.
		PlainTextBinding("FEED_PUSH_TOKEN", spec.FeedPushToken),
	}
	if spec.SelfManage {
		// Both or neither: the Worker's credentials(env) returns null unless it
		// has BOTH, so binding one alone is indistinguishable from binding
		// nothing and reads to the operator as "the feature does not work".
		bindings = append(bindings,
			PlainTextBinding("CF_ACCOUNT_ID", c.AccountID),
			SecretTextBinding("CF_API_TOKEN", c.Token))
	}
	var d1ID string
	if spec.D1 {
		db, err := c.CreateD1(ctx, spec.Name)
		if err != nil {
			return nil, err
		}
		d1ID = db.UUID
		bindings = append(bindings, D1Binding(d1ID))
	}

	// 6. Upload. keep_bindings is set on every upload (see UploadScript).
	if err := c.UploadScript(ctx, UploadSpec{
		Name: spec.Name, Script: spec.Bundle, Bindings: bindings,
	}); err != nil {
		return nil, err
	}

	// 7. Publish on workers.dev, claiming an account subdomain if there is none.
	sub, err := c.AccountSubdomain(ctx)
	if err != nil {
		return nil, err
	}
	if sub == "" {
		candidate, gerr := RandomName()
		if gerr != nil {
			return nil, gerr
		}
		if err := c.SetAccountSubdomain(ctx, candidate); err != nil {
			return nil, err
		}
		sub = candidate
	}
	if err := c.EnableSubdomain(ctx, spec.Name); err != nil {
		return nil, err
	}

	res := &DeployResult{
		Name: spec.Name, Target: spec.Target, Origin: WorkerOrigin(spec.Name, sub),
		SecurePath: spec.SecurePath, FeedPushToken: spec.FeedPushToken,
		KVNamespaceID: kvID, D1DatabaseID: d1ID,
		Updated: spec.Update, SelfManage: spec.SelfManage,
	}
	workersDevOrigin := res.Origin

	// 8. Optional custom domain.
	if host := strings.TrimSpace(spec.Domain); host != "" {
		zoneID, _, err := c.FindZone(ctx, host)
		if err != nil {
			return nil, err
		}
		if err := c.AttachDomain(ctx, spec.Name, host, zoneID); err != nil {
			return nil, err
		}
		res.Hostname = host
		res.Origin = "https://" + host
	}

	res.PanelURL = res.Origin + "/" + res.SecurePath + "/panel"
	res.SubTemplate = res.Origin + "/" + res.SecurePath + "/sub/<sub_token>"
	res.DoHURL = res.Origin + "/" + res.SecurePath + "/dns-query"

	// 9. Prove it serves before anyone is handed these URLs.
	//
	// Probed on the workers.dev origin even when a custom domain was attached:
	// a fresh custom hostname needs DNS and certificate provisioning that can
	// take minutes, so probing it would report a healthy Worker as broken. The
	// workers.dev route is live within seconds and exercises the same isolate.
	if !spec.SkipVerify {
		health, err := verifyAndHeal(ctx, c, spec, workersDevOrigin, kvID, bindings)
		res.Health = &health
		if err != nil {
			return res, err
		}
	}

	// 10. Register the cron trigger the Worker's scheduled() handler runs on.
	//
	// Last, deliberately: verifyAndHeal can DELETE and re-upload the script, and
	// a script delete takes its schedules with it. Registering before the probe
	// would leave a healed Worker with no trigger at all — the same silent
	// no-op, just harder to spot.
	//
	// A failure here is a warning, not an error: the Worker is deployed and
	// serving at this point, and failing the whole request would send an
	// operator hunting for something that is actually running. What they lose
	// is the periodic refresh, which is what the warning says.
	if err := c.PutSchedules(ctx, spec.Name, DefaultCrons); err != nil {
		res.Warnings = append(res.Warnings,
			"deployed, but the cron trigger could not be registered: "+err.Error()+
				" — clean-IP refresh, external-sub merge and the update check will not run on their own; "+
				"add the schedule ("+strings.Join(DefaultCrons, ", ")+") under the Worker's Settings → Triggers.")
	}
	return res, nil
}

// verifyAndHeal probes the Worker and, if it threw, recreates it once.
//
// Recreating means DELETING the script and uploading it again under the same
// name. That is safe for the thing that actually matters: a script delete does
// not touch the KV namespace, so the Worker's secure path, VLESS UUID and
// trojan password all survive in KV and it comes back with the same identity
// and the same URLs — nothing has to be redistributed to anyone already holding
// a config. Measured on a real account: this is what cleared a Worker that was
// throwing 1101 with settings byte-identical to a healthy twin.
//
// It recreates ONLY on a 1101. A probe that could not reach Cloudflare, or that
// got some other status, leaves the Worker alone: deleting someone's Worker
// because of a network blip on the panel host would turn a non-problem into an
// outage.
func verifyAndHeal(ctx context.Context, c *Client, spec DeploySpec, origin, kvID string, bindings []Binding) (Health, error) {
	health := VerifyWorker(ctx, origin, spec.SecurePath, spec.Verify)
	if health.OK {
		return health, nil
	}
	if !health.Threw {
		return health, &ErrWorkerUnhealthy{Health: health, Name: spec.Name}
	}

	// One recreate attempt, then report honestly rather than looping.
	if err := c.DeleteScript(ctx, spec.Name); err != nil {
		health.Detail = "the Worker threw an exception and could not be recreated: " + err.Error()
		return health, &ErrWorkerUnhealthy{Health: health, Name: spec.Name}
	}
	if err := c.UploadScript(ctx, UploadSpec{
		Name: spec.Name, Script: spec.Bundle, Bindings: bindings,
	}); err != nil {
		health.Detail = "the Worker threw an exception and the re-upload failed: " + err.Error()
		return health, &ErrWorkerUnhealthy{Health: health, Name: spec.Name}
	}
	if err := c.EnableSubdomain(ctx, spec.Name); err != nil {
		health.Detail = "the Worker was recreated but could not be published: " + err.Error()
		return health, &ErrWorkerUnhealthy{Health: health, Name: spec.Name}
	}

	after := VerifyWorker(ctx, origin, spec.SecurePath, spec.Verify)
	after.Attempts += health.Attempts
	after.Recreated = true
	if after.OK {
		return after, nil
	}
	return after, &ErrWorkerUnhealthy{Health: after, Name: spec.Name}
}

// Destroy deletes the Worker and, unless keepKV, its KV namespace. Every
// subscription URL that Worker served stops resolving immediately.
func Destroy(ctx context.Context, c *Client, name, target string, keepKV bool) error {
	if err := c.requireAccount("edge-delete"); err != nil {
		return err
	}
	if target == "pages" {
		if err := c.DeletePagesProject(ctx, name); err != nil {
			return err
		}
	} else if err := c.DeleteScript(ctx, name); err != nil {
		return err
	}
	if keepKV {
		return nil
	}
	ns, err := c.FindKVNamespace(ctx, KVTitle(name))
	if err != nil {
		// A namespace that is already gone is not a failure of the delete; the
		// Worker — the thing that actually served traffic — is destroyed.
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	return c.DeleteKVNamespace(ctx, ns.ID)
}
