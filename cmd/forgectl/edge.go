package main

// forgectl edge — the ForgeEdge control plane on the CLI (§6). The contract is
// deploy/cloudflare/forgeedge/docs/FORGECTL_EDGE_SPEC.md; every payload and
// failure mode there is implemented here.
//
// Credential policy, restated because operators reasonably assume the two are
// equivalent and they are not:
//
//   OAuth + PKCE (default) — Cloudflare issues a token to this machine, nothing
//     long-lived is written into the Worker, and the refresh token stays under
//     the operator's own config directory at 0600.
//
//   --api-token — used for that invocation only. A token written INTO a Worker
//     (the CF_API_TOKEN binding) is readable by anyone who can deploy to that
//     account; this command never does that.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/store"
)

// Exit codes (FORGECTL_EDGE_SPEC.md).
const (
	exitOK           = 0
	exitFailure      = 1
	exitUsage        = 2
	exitAuth         = 3
	exitNameTaken    = 4
	exitNotFound     = 5
	exitFeedRejected = 6
)

// exitError carries a specific process exit code out of a subcommand.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withExit(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: code, err: err}
}

// printRemediation writes the "here is what to do about it" line that a typed
// edge error carries. Without this the operator sees only the diagnosis, and
// the whole point of building the remediation was that they should not have to
// go looking for it.
func printRemediation(w io.Writer, err error) {
	if e, ok := edge.AsError(err); ok && e.Remediation != "" {
		fmt.Fprintln(w, "  →", e.Remediation)
	}
}

// exitCodeFor maps an error to the process exit code. Anything that is not
// explicitly classified is a generic failure, which is the safe default: a
// caller scripting against these codes must never read "1" as success.
func exitCodeFor(err error) int {
	if err == nil {
		return exitOK
	}
	var ex *exitError
	if errors.As(err, &ex) {
		return ex.code
	}
	if e, ok := edge.AsError(err); ok {
		switch e.Kind {
		case edge.KindAuth, edge.KindPermission, edge.KindNoCredentials:
			return exitAuth
		case edge.KindConflict:
			return exitNameTaken
		case edge.KindNotFound:
			return exitNotFound
		}
	}
	return exitFailure
}

func cmdEdge(args []string) error {
	if len(args) == 0 {
		edgeUsage()
		return withExit(exitUsage, errors.New("edge needs a subcommand"))
	}
	switch args[0] {
	case "deploy":
		return cmdEdgeDeploy(args[1:])
	case "update":
		return cmdEdgeUpdate(args[1:])
	case "delete":
		return cmdEdgeDelete(args[1:])
	case "status":
		return cmdEdgeStatus(args[1:])
	case "push":
		return cmdEdgePush(args[1:])
	case "rotate-path":
		return cmdEdgeRotatePath(args[1:])
	case "token-url":
		fmt.Println(edge.TokenURL())
		return nil
	case "-h", "--help", "help":
		edgeUsage()
		return nil
	default:
		edgeUsage()
		return withExit(exitUsage, fmt.Errorf("unknown edge subcommand %q", args[0]))
	}
}

func edgeUsage() {
	fmt.Print(`forgectl edge — deploy and feed a ForgeEdge Cloudflare Worker

Usage:
  forgectl edge deploy      [--name n] [--target workers] [--domain d] [--api-token t]
                            [--account id] [--bundle worker.js] [--secure-path p]
                            [--d1] [--force] [--self-manage] [--feed] [--json]
  forgectl edge update      [--name n | --all] [--check-only] [--force] [--bundle f]
  forgectl edge delete      --name n [--yes] [--keep-kv]
  forgectl edge status      [--name n | --all] [--password p] [--json]
  forgectl edge push        [--name n | --all] [--dry-run] [--feed file]
  forgectl edge rotate-path --name n [--yes] --password p
  forgectl edge token-url

Credentials:
  Without --api-token, deploy/update/delete run Cloudflare's OAuth + PKCE flow in
  a browser and keep the refresh token at ` + edge.TokenPath() + ` (0600).
  There is no OS keyring integration; that file IS the store.
  With --api-token the token is used for this invocation only and never stored.

Exit codes: 0 ok · 1 failure · 2 usage · 3 authorisation · 4 name taken
            5 worker not found · 6 feed rejected by the edge
`)
}

// edgeCreds resolves a Cloudflare client: an explicit token when given,
// otherwise a stored OAuth token, otherwise the interactive PKCE flow.
func edgeCreds(ctx context.Context, apiToken, account, apiBase string, allowOAuth bool) (*edge.Client, error) {
	token := strings.TrimSpace(apiToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("CF_API_TOKEN"))
	}
	if token == "" {
		if !allowOAuth {
			return nil, edge.ErrNoCredentials("edge")
		}
		ts, err := edge.LoadToken(edge.TokenPath())
		if err == nil && ts.AccessToken != "" && !ts.Expired(time.Now()) {
			token = ts.AccessToken
			if account == "" {
				account = ts.AccountID
			}
		} else {
			o := &edge.OAuth{}
			fresh, aerr := o.Authorize(ctx)
			if aerr != nil {
				return nil, aerr
			}
			token = fresh.AccessToken
			if err := edge.SaveToken(edge.TokenPath(), fresh); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not store the authorisation: %v\n", err)
			} else {
				fmt.Printf("Authorisation stored at %s (0600).\n", edge.TokenPath())
			}
		}
	}
	c := edge.NewClient(token, strings.TrimSpace(account))
	if apiBase != "" {
		c.BaseURL = apiBase
	}
	if c.AccountID == "" {
		accounts, err := c.ListAccounts(ctx)
		if err != nil {
			return nil, err
		}
		switch len(accounts) {
		case 0:
			return nil, &edge.Error{Op: "resolve-account", Kind: edge.KindAuth,
				Message:     "this credential can see no Cloudflare accounts",
				Remediation: "check the token's Account Resources, or pass --account with the id from any zone's Overview sidebar."}
		case 1:
			c.AccountID = accounts[0].ID
		default:
			var b strings.Builder
			for _, a := range accounts {
				fmt.Fprintf(&b, "\n  %s  %s", a.ID, a.Name)
			}
			return nil, &edge.Error{Op: "resolve-account", Kind: edge.KindValidation,
				Message:     "this credential spans several accounts, so the target is ambiguous",
				Remediation: "re-run with --account <id>. Accounts visible to this credential:" + b.String()}
		}
	}
	return c, nil
}

// readBundle loads the Worker bundle. It is never fetched from the network:
// ForgeEdge does not self-update from remote code, and neither does its
// installer.
func readBundle(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		// The conventional build output, relative to a source checkout.
		path = filepath.Join("deploy", "cloudflare", "forgeedge", "dist", "worker.js")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &edge.Error{Op: "read-bundle", Kind: edge.KindValidation,
			Message: "could not read the Worker bundle at " + path + ": " + err.Error(),
			Remediation: "build it with `cd deploy/cloudflare/forgeedge && bun run build`, " +
				"or point --bundle at a worker.js from a release artifact.", Cause: err}
	}
	return raw, nil
}

func cmdEdgeDeploy(args []string) error {
	fs := flag.NewFlagSet("edge deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name       = fs.String("name", "", "Worker/Pages project name (default: forgeedge-<6 hex>)")
		target     = fs.String("target", "workers", "workers | pages")
		domain     = fs.String("domain", "", "custom domain to attach (its zone must be in this account)")
		apiToken   = fs.String("api-token", "", "skip OAuth and use this token for this invocation only")
		account    = fs.String("account", "", "account id, when the credential spans several")
		bundle     = fs.String("bundle", "", "path to the built worker.js")
		securePath = fs.String("secure-path", "", "secure path to bind (default: freshly generated)")
		useD1      = fs.Bool("d1", false, "also create and bind a D1 database")
		force      = fs.Bool("force", false, "overwrite a Worker that already exists")
		selfManage = fs.Bool("self-manage", false,
			"bind this account's Cloudflare credential into the Worker so its own panel can report "+
				"its deployment (a token in a binding is readable by anyone who can deploy to this account)")
		skipVerify = fs.Bool("skip-verify", false,
			"return as soon as the upload is accepted, without checking the Worker actually serves. "+
				"Only for a host with no route to the edge: \"the API accepted it\" and \"it serves\" "+
				"are not the same thing, and the gap is what hands somebody a dead panel link")
		pushFeed = fs.Bool("feed", false, "push the canonical feed immediately after deploying")
		data     = fs.String("data", defaultDataDir(), "panel data directory (for registering the deployment)")
		apiBase  = fs.String("api-base", "", "override the Cloudflare API root (testing/proxying)")
		asJSON   = fs.Bool("json", false, "machine-readable output")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	raw, err := readBundle(*bundle)
	if err != nil {
		return err
	}
	if *name == "" {
		n, err := edge.RandomName()
		if err != nil {
			return err
		}
		*name = n
	}
	// The refusal belongs here, not in edge.Deploy: edgeCreds is the only code
	// that knows whether a token came from --api-token, the environment or the
	// PKCE flow, and edge.Client carries no provenance.
	if *selfManage && strings.TrimSpace(*apiToken) == "" && strings.TrimSpace(os.Getenv("CF_API_TOKEN")) == "" {
		return withExit(exitUsage, &edge.Error{Op: "edge-deploy", Kind: edge.KindValidation,
			Message: "--self-manage needs an explicit API token",
			Remediation: "pass --api-token (or set CF_API_TOKEN). The OAuth token this command would " +
				"otherwise use is short-lived, and binding an expiring token into a Worker produces a " +
				"Deployment panel that silently rots."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c, err := edgeCreds(ctx, *apiToken, *account, *apiBase, true)
	if err != nil {
		return err
	}
	res, err := edge.Deploy(ctx, c, edge.DeploySpec{
		Name: *name, Target: *target, SecurePath: *securePath, Bundle: raw,
		Domain: *domain, Force: *force, D1: *useD1, SkipVerify: *skipVerify,
		SelfManage: *selfManage,
	})
	if err != nil {
		// A Worker that uploaded but does not serve is still registered locally
		// so `forgectl edge update` can retry it by name — but it is reported as
		// the failure it is, not as a deploy that worked.
		if res != nil && edge.IsUnhealthy(err) {
			registerEdgeLocally(*data, res, c.AccountID)
		}
		return err
	}
	registerEdgeLocally(*data, res, c.AccountID)
	if *asJSON {
		return printJSON(res)
	}
	printDeployResult(res)
	if *pushFeed {
		fmt.Println()
		return cmdEdgePush([]string{"--name", res.Name, "--data", *data})
	}
	return nil
}

func printDeployResult(res *edge.DeployResult) {
	verb := "deployed"
	if res.Updated {
		verb = "updated"
	}
	fmt.Printf(`ForgeEdge %s.
  Worker        %s
  URL           %s
  Panel         %s
  Subscription  %s
  DoH           %s
  Backend mode  off  (edge terminates VLESS/Trojan over WS; TCP only, DNS-over-UDP only)

Set an admin password at the panel URL before sharing anything.
`, verb, res.Name, res.Origin, res.PanelURL, res.SubTemplate, res.DoHURL)
}

// registerEdgeLocally records the deployment in the panel DB. A failure here is
// reported, never fatal: the Worker is live either way, and saying "deploy
// failed" would send the operator hunting for something that is running.
func registerEdgeLocally(data string, res *edge.DeployResult, accountID string) {
	db, err := store.Open(filepath.Join(data, "forgepanel.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: deployed, but not registered in the panel (%v).\n"+
			"      Register it in the panel UI, or re-run on the panel host.\n", err)
		return
	}
	defer db.Close()
	d := &store.EdgeDeployment{
		Name: res.Name, Target: res.Target, Origin: res.Origin,
		SecurePath: res.SecurePath, AccountID: accountID, SelfManage: res.SelfManage,
	}
	if existing, err := db.EdgeDeploymentByName(res.Name); err == nil {
		existing.Origin, existing.SecurePath, existing.AccountID = res.Origin, res.SecurePath, accountID
		// Also on the update branch: a --force --self-manage redeploy over a row
		// that says false would leave the Worker holding a credential the next
		// `edge update` strips, with nothing anywhere reporting it.
		existing.SelfManage = res.SelfManage
		if err := db.SaveEdgeDeployment(existing); err != nil {
			fmt.Fprintf(os.Stderr, "note: deployed, but the panel row could not be updated: %v\n", err)
		}
		return
	}
	if err := db.CreateEdgeDeployment(d); err != nil {
		fmt.Fprintf(os.Stderr, "note: deployed, but not registered in the panel: %v\n", err)
		return
	}
	fmt.Printf("Registered in the panel (id %d). Add its push token from the Worker's status page to enable feeding.\n", d.ID)
}

func cmdEdgeUpdate(args []string) error {
	fs := flag.NewFlagSet("edge update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name       = fs.String("name", "", "Worker name")
		all        = fs.Bool("all", false, "every registered deployment")
		checkOnly  = fs.Bool("check-only", false, "only report whether a newer release exists")
		force      = fs.Bool("force", false, "allow a downgrade")
		skipVerify = fs.Bool("skip-verify", false,
			"return as soon as the upload is accepted, without checking the Worker still serves. "+
				"An update that leaves a Worker throwing is worse than a failed one: it was working before")
		apiToken = fs.String("api-token", "", "skip OAuth and use this token")
		account  = fs.String("account", "", "account id")
		bundle   = fs.String("bundle", "", "path to the built worker.js")
		password = fs.String("password", "", "the edge admin password, to read its version back")
		repo     = fs.String("repo", edge.UpdateRepo, "GitHub repo to check releases against")
		data     = fs.String("data", defaultDataDir(), "panel data directory")
		apiBase  = fs.String("api-base", "", "override the Cloudflare API root")
		asJSON   = fs.Bool("json", false, "machine-readable output")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	targets, err := edgeTargets(*data, *name, *all)
	if err != nil {
		return err
	}

	if *checkOnly {
		current := "0.0.0"
		if len(targets) > 0 && *password != "" {
			wc := edge.NewWorkerClient(targets[0].Origin, targets[0].SecurePath)
			if st, err := wc.Status(ctx, *password); err == nil {
				current = st.Version
			}
		}
		info, err := edge.CheckForUpdate(ctx, nil, *repo, current)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(info)
		}
		if info.UpdateAvailable {
			fmt.Printf("ForgeEdge %s is available (running %s): %s\n", info.Latest, info.Current, info.ReleaseURL)
		} else {
			fmt.Printf("%s is current.\n", info.Current)
		}
		return nil
	}

	raw, err := readBundle(*bundle)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return withExit(exitUsage, errors.New("edge update needs --name or --all"))
	}
	// The same refusal the deploy path carries, and it belongs here for a
	// stronger reason: this is the DEFAULT invocation. `forgectl edge update
	// --all` with no token falls through edgeCreds to the stored OAuth access
	// token — OAuth being the documented preferred flow — and the loop below
	// re-binds whatever it gets as CF_API_TOKEN on every self-managed target.
	// So the path that runs unattended was the one without the guard.
	//
	// Before edgeCreds, not after: reaching it starts a PKCE flow that waits
	// five minutes for a browser callback, and refusing after a partial upload
	// would leave some Workers rebound and some not.
	if strings.TrimSpace(*apiToken) == "" && strings.TrimSpace(os.Getenv("CF_API_TOKEN")) == "" {
		var selfManaged []string
		for _, t := range targets {
			if t.SelfManage {
				selfManaged = append(selfManaged, t.Name)
			}
		}
		if len(selfManaged) > 0 {
			return withExit(exitUsage, &edge.Error{Op: "edge-update", Kind: edge.KindValidation,
				Message: "updating a self-managed Worker needs an explicit API token: " +
					strings.Join(selfManaged, ", "),
				Remediation: "pass --api-token (or set CF_API_TOKEN). This update re-binds the " +
					"credential the Worker's own Deployment panel uses, and the OAuth token this " +
					"command would otherwise reach for is short-lived — binding it produces a panel " +
					"that works today and silently rots. --name a Worker that is not self-managed " +
					"to update it without one."})
		}
	}
	c, err := edgeCreds(ctx, *apiToken, *account, *apiBase, true)
	if err != nil {
		return err
	}
	for _, t := range targets {
		// keep_bindings preserves KV and D1, so config, users and the secure
		// path all survive the re-upload (see edge.UploadScript). It does NOT
		// cover the text bindings: those are a closed list resent on every
		// upload, so the self-manage credential has to be replayed from the
		// registered row or this update silently strips it.
		res, err := edge.Deploy(ctx, c, edge.DeploySpec{
			Name: t.Name, Target: t.Target, SecurePath: t.SecurePath,
			Bundle: raw, Update: true, Force: *force, SkipVerify: *skipVerify,
			SelfManage: t.SelfManage,
		})
		if err != nil {
			return err
		}
		fmt.Printf("updated %s → %s\n", res.Name, res.Origin)
	}
	return nil
}

func cmdEdgeDelete(args []string) error {
	fs := flag.NewFlagSet("edge delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name     = fs.String("name", "", "Worker name (required)")
		yes      = fs.Bool("yes", false, "skip the confirmation prompt")
		keepKV   = fs.Bool("keep-kv", false, "keep the KV namespace (config, users, secure path)")
		apiToken = fs.String("api-token", "", "skip OAuth and use this token")
		account  = fs.String("account", "", "account id")
		target   = fs.String("target", "workers", "workers | pages")
		data     = fs.String("data", defaultDataDir(), "panel data directory")
		apiBase  = fs.String("api-base", "", "override the Cloudflare API root")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	if strings.TrimSpace(*name) == "" {
		return withExit(exitUsage, errors.New("edge delete needs --name"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Say exactly what dies, and what the last feed put on it, before anything
	// is destroyed. The last push status is the only honest source for the user
	// count here — nothing else on this host knows what that Worker is serving.
	origin, lastPush := "", ""
	if d, err := openEdgeDeployment(*data, *name); err == nil {
		origin, lastPush = d.Origin, d.LastStatus
	}
	if !*yes {
		fmt.Printf("This destroys the Worker %q", *name)
		if origin != "" {
			fmt.Printf(" at %s", origin)
		}
		fmt.Print(".\nEvery subscription URL it serves stops working immediately.\n")
		if lastPush != "" {
			fmt.Printf("Last feed pushed to it: %s\n", lastPush)
		}
		fmt.Println("Re-run with --yes to proceed.")
		return withExit(exitUsage, errors.New("refusing to delete without --yes"))
	}
	c, err := edgeCreds(ctx, *apiToken, *account, *apiBase, true)
	if err != nil {
		return err
	}
	if err := edge.Destroy(ctx, c, *name, *target, *keepKV); err != nil {
		return err
	}
	if db, err := store.Open(filepath.Join(*data, "forgepanel.db")); err == nil {
		defer db.Close()
		if d, err := db.EdgeDeploymentByName(*name); err == nil {
			_ = db.DeleteEdgeDeployment(d.ID)
		}
	}
	fmt.Printf("deleted %s\n", *name)
	return nil
}
