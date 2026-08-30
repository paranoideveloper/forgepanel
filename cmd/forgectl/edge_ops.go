package main

// The read/feed half of `forgectl edge`: status, push and rotate-path all talk
// to a DEPLOYED Worker rather than to the Cloudflare API, so they need an origin
// and a secure path — either from the panel DB or given explicitly on the
// command line (which is also how they are tested against a mock edge).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
)

// edgeTarget is one edge to act on.
type edgeTarget struct {
	ID         uint
	Name       string
	Target     string
	Origin     string
	SecurePath string
	PushToken  string
	// SelfManage is carried so `edge update` can re-send the Cloudflare
	// credential binding. Every upload sends a closed bindings list, so a
	// binding this projection forgets is a binding the update strips.
	SelfManage bool
}

// openEdgeDeployment reads one registered edge from the panel DB.
func openEdgeDeployment(data, name string) (*store.EdgeDeployment, error) {
	db, err := store.Open(filepath.Join(data, "forgepanel.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.EdgeDeploymentByName(name)
}

// edgeTargets resolves --name / --all against the panel DB.
func edgeTargets(data, name string, all bool) ([]edgeTarget, error) {
	if strings.TrimSpace(name) == "" && !all {
		return nil, nil
	}
	db, err := store.Open(filepath.Join(data, "forgepanel.db"))
	if err != nil {
		return nil, &edge.Error{Op: "edge-targets", Kind: edge.KindNotFound,
			Message:     "could not open the panel database at " + data + ": " + err.Error(),
			Remediation: "run this on the panel host, pass --data <dir>, or address the edge directly with --origin/--secure-path.",
			Cause:       err}
	}
	defer db.Close()
	var rows []store.EdgeDeployment
	if all {
		rows, err = db.ListEdgeDeployments()
		if err != nil {
			return nil, err
		}
	} else {
		d, err := db.EdgeDeploymentByName(name)
		if err != nil {
			return nil, &edge.Error{Op: "edge-targets", Kind: edge.KindNotFound,
				Message:     "no registered edge named " + name,
				Remediation: "list them with `forgectl edge status --all`, or register it in the panel first."}
		}
		rows = []store.EdgeDeployment{*d}
	}
	out := make([]edgeTarget, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, edgeTarget{ID: r.ID, Name: r.Name, Target: r.Target,
			Origin: r.Origin, SecurePath: r.SecurePath, PushToken: r.PushToken,
			SelfManage: r.SelfManage})
	}
	return out, nil
}

// resolveEdgeTargets prefers an explicit --origin over the DB, so a machine with
// no panel database can still drive an edge.
func resolveEdgeTargets(data, name string, all bool, origin, securePath, pushToken string) ([]edgeTarget, error) {
	if strings.TrimSpace(origin) != "" {
		n := name
		if n == "" {
			n = origin
		}
		return []edgeTarget{{Name: n, Target: "workers", Origin: strings.TrimSuffix(origin, "/"),
			SecurePath: strings.Trim(securePath, "/"), PushToken: pushToken}}, nil
	}
	targets, err := edgeTargets(data, name, all)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, withExit(exitUsage, errors.New("nothing to act on: pass --name, --all, or --origin with --secure-path"))
	}
	return targets, nil
}

func cmdEdgeStatus(args []string) error {
	fs := flag.NewFlagSet("edge status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name       = fs.String("name", "", "Worker name")
		all        = fs.Bool("all", false, "every registered deployment")
		password   = fs.String("password", "", "the edge admin password (its status API is session-authenticated)")
		origin     = fs.String("origin", "", "address the edge directly instead of using the panel DB")
		securePath = fs.String("secure-path", "", "secure path, with --origin")
		data       = fs.String("data", defaultDataDir(), "panel data directory")
		asJSON     = fs.Bool("json", false, "machine-readable output")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	if !*all && *name == "" && *origin == "" {
		*all = true
	}
	targets, err := resolveEdgeTargets(*data, *name, *all, *origin, *securePath, "")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type row struct {
		Name   string             `json:"name"`
		Target string             `json:"target"`
		Origin string             `json:"origin"`
		Status *edge.WorkerStatus `json:"status,omitempty"`
		Error  string             `json:"error,omitempty"`
	}
	out := make([]row, 0, len(targets))
	var firstErr error
	for _, t := range targets {
		r := row{Name: t.Name, Target: t.Target, Origin: t.Origin}
		wc := edge.NewWorkerClient(t.Origin, t.SecurePath)
		st, err := wc.Status(ctx, *password)
		if err != nil {
			// Reported, not hidden: an edge that cannot be reached is exactly
			// what an operator runs this command to find out about.
			r.Error = err.Error()
			if firstErr == nil {
				firstErr = err
			}
		} else {
			r.Status = st
		}
		out = append(out, r)
	}
	if *asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
		return firstErr
	}
	for _, r := range out {
		fmt.Printf("%-22s %-9s %s\n", r.Name, r.Target, r.Origin)
		if r.Error != "" {
			fmt.Printf("  unreachable   %s\n", r.Error)
			continue
		}
		st := r.Status
		fmt.Printf("  version       %s\n", st.Version)
		fmt.Printf("  users         %d (feed generated %s)\n", st.Users, orNone(st.FeedGeneratedAt))
		fmt.Printf("  backend       %s\n", orNone(st.BackendMode))
		fmt.Printf("  clean IPs     %d (refreshed %s)\n", st.CleanIPs.Count, orNone(st.CleanIPs.UpdatedAt))
		fmt.Printf("  secure path   rotated %s\n", orNone(st.SecurePathRotatedAt))
	}
	return firstErr
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "never"
	}
	return s
}

func cmdEdgePush(args []string) error {
	fs := flag.NewFlagSet("edge push", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name       = fs.String("name", "", "Worker name")
		all        = fs.Bool("all", false, "every registered deployment")
		dryRun     = fs.Bool("dry-run", false, "print the document and per-user node counts without sending")
		feedFile   = fs.String("feed", "", "read the canonical feed from this file instead of the panel")
		panelURL   = fs.String("panel", "", "panel base URL to fetch the feed from (default: the local panel)")
		pullToken  = fs.String("pull-token", "", "bearer for the panel's feed endpoint (default: read from the panel DB)")
		origin     = fs.String("origin", "", "address the edge directly instead of using the panel DB")
		securePath = fs.String("secure-path", "", "secure path, with --origin")
		pushToken  = fs.String("push-token", "", "feed push token, with --origin")
		data       = fs.String("data", defaultDataDir(), "panel data directory")
		asJSON     = fs.Bool("json", false, "machine-readable output")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	doc, err := loadCanonicalFeed(*feedFile, *panelURL, *pullToken, *data)
	if err != nil {
		return err
	}
	if *dryRun {
		return printFeedDryRun(doc, *asJSON)
	}
	if !*all && *name == "" && *origin == "" {
		*all = true
	}
	targets, err := resolveEdgeTargets(*data, *name, *all, *origin, *securePath, *pushToken)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	failures := 0
	for _, t := range targets {
		token := t.PushToken
		if token == "" {
			token = *pushToken
		}
		if token == "" {
			failures++
			fmt.Fprintf(os.Stderr, "%s: no push token stored; read feedPushToken from the Worker's status page\n", t.Name)
			continue
		}
		feedURL := strings.TrimSuffix(t.Origin, "/") + "/" + strings.Trim(t.SecurePath, "/") + "/feed"
		res, err := edge.PushFeed(ctx, nil, feedURL, token, doc)
		if err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "%s: %v\n", t.Name, err)
			continue
		}
		fmt.Printf("%s: accepted %d user(s), %d shared node(s)\n", t.Name, res.Users, res.SharedNodes)
		// Warnings are ALWAYS surfaced: each one is a user or node the edge
		// dropped, and those subscribers get a short list without knowing it.
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}
	if failures > 0 {
		return withExit(exitFeedRejected, fmt.Errorf("%d of %d edge(s) rejected the feed", failures, len(targets)))
	}
	return nil
}

// printFeedDryRun shows what would be sent, per user.
func printFeedDryRun(doc map[string]any, asJSON bool) error {
	if asJSON {
		return printJSON(doc)
	}
	users, _ := doc["users"].([]any)
	fmt.Printf("canonical feed: version %v, generated %v, %d user(s)\n",
		doc["version"], doc["generated_at"], len(users))
	for _, raw := range users {
		u, _ := raw.(map[string]any)
		nodes, _ := u["nodes"].([]any)
		fmt.Printf("  %-24v %2d node(s)  enabled=%v\n", u["email"], len(nodes), u["enabled"])
	}
	if shared, ok := doc["shared_nodes"].([]any); ok {
		fmt.Printf("  shared: %d node(s)\n", len(shared))
	}
	fmt.Println("(dry run — nothing was sent)")
	return nil
}

// loadCanonicalFeed sources the document to push. The panel is the only thing
// that builds a feed — this never rebuilds one, so the pushed document and the
// one served at /api/edge/feed can never disagree.
func loadCanonicalFeed(file, panelBase, pullToken, data string) (map[string]any, error) {
	var raw []byte
	if strings.TrimSpace(file) != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, &edge.Error{Op: "load-feed", Kind: edge.KindValidation,
				Message: "could not read " + file + ": " + err.Error(), Cause: err}
		}
		raw = b
	} else {
		b, err := fetchPanelFeed(panelBase, pullToken, data)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &edge.Error{Op: "load-feed", Kind: edge.KindValidation,
			Message:     "the feed is not valid JSON: " + err.Error(),
			Remediation: "if this came from the panel, check that /api/edge/feed is reachable and the pull token is right.",
			Cause:       err}
	}
	return doc, nil
}

// fetchPanelFeed GETs the panel's own canonical feed. The token comes from the
// panel database (the same row /api/admin/edge/feed-token mints), so the CLI
// needs no separate credential on the panel host.
func fetchPanelFeed(panelBase, pullToken, data string) ([]byte, error) {
	if strings.TrimSpace(pullToken) == "" || strings.TrimSpace(panelBase) == "" {
		db, err := store.Open(filepath.Join(data, "forgepanel.db"))
		if err != nil {
			return nil, &edge.Error{Op: "fetch-feed", Kind: edge.KindNotFound,
				Message:     "could not open the panel database at " + data + ": " + err.Error(),
				Remediation: "run this on the panel host, or pass --feed <file> with a document exported from the panel.",
				Cause:       err}
		}
		defer db.Close()
		if strings.TrimSpace(pullToken) == "" {
			// Through the registry like every other reader, so the CLI cannot
			// drift from the panel on what this key is called or holds.
			pullToken = settings.NewValues(db).String("edge_feed_pull_token")
		}
		if strings.TrimSpace(panelBase) == "" {
			cfg, err := loadLocalConfig(data)
			if err == nil {
				panelBase = strings.TrimSuffix(panelURL(cfg.Panel()), cfg.Panel().AdminPath)
			}
		}
	}
	if strings.TrimSpace(pullToken) == "" {
		return nil, &edge.Error{Op: "fetch-feed", Kind: edge.KindAuth,
			Message:     "the panel has no feed pull token yet",
			Remediation: "mint one in the panel (GET /api/admin/edge/feed-token), then re-run."}
	}
	base := strings.TrimSuffix(strings.TrimSpace(panelBase), "/")
	if base == "" {
		base = "http://127.0.0.1:2053"
	}
	req, err := http.NewRequest(http.MethodGet, base+"/api/edge/feed", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+pullToken)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, &edge.Error{Op: "fetch-feed", Kind: edge.KindNetwork,
			Message:     "could not reach the panel at " + base + ": " + err.Error(),
			Remediation: "is the panel running? Otherwise pass --panel <url> or --feed <file>.", Cause: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &edge.Error{Op: "fetch-feed", Kind: edge.KindAuth, Status: resp.StatusCode,
			Message: fmt.Sprintf("the panel returned %d for /api/edge/feed: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return body, nil
}

func cmdEdgeRotatePath(args []string) error {
	fs := flag.NewFlagSet("edge rotate-path", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		name       = fs.String("name", "", "Worker name")
		yes        = fs.Bool("yes", false, "skip the confirmation prompt")
		password   = fs.String("password", "", "the edge admin password (required)")
		origin     = fs.String("origin", "", "address the edge directly instead of using the panel DB")
		securePath = fs.String("secure-path", "", "current secure path, with --origin")
		data       = fs.String("data", defaultDataDir(), "panel data directory")
	)
	if err := fs.Parse(args); err != nil {
		return withExit(exitUsage, err)
	}
	if !*yes {
		fmt.Print(`Rotating the secure path kills EVERY existing URL immediately:
the panel, the API, and every subscription your users already have.
The admin session is invalidated too, and subscriptions must be re-sent.

Re-run with --yes to proceed.
`)
		return withExit(exitUsage, errors.New("refusing to rotate without --yes"))
	}
	if strings.TrimSpace(*password) == "" {
		return withExit(exitUsage, errors.New("edge rotate-path needs --password (the edge admin password)"))
	}
	targets, err := resolveEdgeTargets(*data, *name, false, *origin, *securePath, "")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	t := targets[0]
	wc := edge.NewWorkerClient(t.Origin, t.SecurePath)
	fresh, err := wc.RotatePath(ctx, *password)
	if err != nil {
		return err
	}
	// Persist the new path, or every later command addresses a dead URL.
	if t.ID != 0 {
		if db, err := store.Open(filepath.Join(*data, "forgepanel.db")); err == nil {
			defer db.Close()
			if d, err := db.EdgeDeploymentByID(t.ID); err == nil {
				d.SecurePath = fresh
				if err := db.SaveEdgeDeployment(d); err != nil {
					fmt.Fprintf(os.Stderr, "warning: rotated, but the panel row still holds the old path: %v\n", err)
				}
			}
		}
	}
	fmt.Printf("rotated. New panel: %s/%s/panel\n", t.Origin, fresh)
	fmt.Println("Re-send subscription URLs to every user; the old ones are dead.")
	return nil
}
