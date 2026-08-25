package edgebot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/edge"
)

// Ops is every Cloudflare / deployed-Worker action the bot performs, behind an
// interface so the command router can be unit-tested against a fake. The live
// implementation wraps internal/edge — the same engine the panel uses — so a
// Worker deployed here is identical to one the panel deploys.
//
// Credentialled operations take the caller's own (token, account); Worker
// operations take a Deployment, whose FeedPushToken authenticates every call.
type Ops interface {
	// VerifyCreds confirms a token works and returns the account id to store
	// (resolving it when the caller left it blank and the token sees exactly one).
	VerifyCreds(ctx context.Context, token, account string) (string, error)

	Deploy(ctx context.Context, token, account, name, domain string) (Deployment, error)
	Update(ctx context.Context, token, account string, d Deployment) error
	Destroy(ctx context.Context, token, account string, d Deployment, keepKV bool) error
	AttachDomain(ctx context.Context, token, account string, d Deployment, host string) error

	Status(ctx context.Context, d Deployment) (*edge.WorkerStatus, error)
	GetConfig(ctx context.Context, d Deployment) (map[string]any, error)
	PutConfig(ctx context.Context, d Deployment, cfg map[string]any) (map[string]any, error)
	RefreshCleanIPs(ctx context.Context, d Deployment) (*edge.CleanIPStore, error)
	ProbeCleanIP(ctx context.Context, d Deployment, target string) (*edge.CleanIPProbe, error)
	RefreshExternal(ctx context.Context, d Deployment) (int, error)
	RotatePath(ctx context.Context, d Deployment) (string, error)

	Warp(ctx context.Context, d Deployment) (int, error)
	WarpConf(ctx context.Context, d Deployment) (plain, pro string, err error)
}

// liveOps is the production Ops backed by real Cloudflare calls.
type liveOps struct {
	apiBase string // "" in production; an httptest base in tests of the live path
}

// NewOps returns the production Ops implementation.
func NewOps() Ops { return &liveOps{} }

// client builds a Cloudflare API client, resolving the account when blank.
func (o *liveOps) client(ctx context.Context, token, account string) (*edge.Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, &edge.Error{Op: "edgebot", Kind: edge.KindNoCredentials,
			Message:     "no Cloudflare token stored",
			Remediation: "run /cf <api_token> <account_id> first."}
	}
	c := edge.NewClient(token, strings.TrimSpace(account))
	if o.apiBase != "" {
		c.BaseURL = o.apiBase
	}
	if c.AccountID == "" {
		accts, err := c.ListAccounts(ctx)
		if err != nil {
			return nil, err
		}
		switch len(accts) {
		case 0:
			return nil, &edge.Error{Op: "edgebot", Kind: edge.KindAuth,
				Message:     "this token can see no Cloudflare accounts",
				Remediation: "check the token's Account Resources, or pass the account id: /cf <token> <account_id>."}
		case 1:
			c.AccountID = accts[0].ID
		default:
			var b strings.Builder
			for _, a := range accts {
				fmt.Fprintf(&b, "\n  %s  %s", a.ID, a.Name)
			}
			return nil, &edge.Error{Op: "edgebot", Kind: edge.KindValidation,
				Message:     "this token spans several accounts, so the target is ambiguous",
				Remediation: "re-send with the account id: /cf <token> <account_id>. Accounts:" + b.String()}
		}
	}
	return c, nil
}

func (o *liveOps) VerifyCreds(ctx context.Context, token, account string) (string, error) {
	c, err := o.client(ctx, token, account)
	if err != nil {
		return "", err
	}
	return c.AccountID, nil
}

func (o *liveOps) worker(d Deployment) *edge.WorkerClient {
	wc := edge.NewWorkerClient(d.Origin, d.SecurePath)
	wc.Bearer = d.FeedPushToken // machine credential — no admin password needed
	return wc
}

func (o *liveOps) Deploy(ctx context.Context, token, account, name, domain string) (Deployment, error) {
	c, err := o.client(ctx, token, account)
	if err != nil {
		return Deployment{}, err
	}
	if !edge.HasBundle() {
		return Deployment{}, &edge.Error{Op: "edgebot", Kind: edge.KindServer,
			Message: "no Worker bundle is compiled into this build"}
	}
	if strings.TrimSpace(name) == "" {
		if name, err = edge.RandomName(); err != nil {
			return Deployment{}, err
		}
	}
	res, err := edge.Deploy(ctx, c, edge.DeploySpec{
		Name: name, Target: "workers", Bundle: edge.Bundle(), Domain: strings.TrimSpace(domain),
	})
	if err != nil {
		return Deployment{}, err
	}
	return Deployment{
		Name: res.Name, Origin: res.Origin, SecurePath: res.SecurePath,
		FeedPushToken: res.FeedPushToken, AccountID: c.AccountID, Domain: res.Hostname,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (o *liveOps) Update(ctx context.Context, token, account string, d Deployment) error {
	c, err := o.client(ctx, token, account)
	if err != nil {
		return err
	}
	_, err = edge.Deploy(ctx, c, edge.DeploySpec{
		Name: d.Name, Target: "workers", SecurePath: d.SecurePath,
		Bundle: edge.Bundle(), Update: true, Force: true,
	})
	return err
}

func (o *liveOps) Destroy(ctx context.Context, token, account string, d Deployment, keepKV bool) error {
	c, err := o.client(ctx, token, account)
	if err != nil {
		return err
	}
	return edge.Destroy(ctx, c, d.Name, "workers", keepKV)
}

func (o *liveOps) AttachDomain(ctx context.Context, token, account string, d Deployment, host string) error {
	c, err := o.client(ctx, token, account)
	if err != nil {
		return err
	}
	zoneID, _, err := c.FindZone(ctx, host)
	if err != nil {
		return err
	}
	return c.AttachDomain(ctx, d.Name, host, zoneID)
}

func (o *liveOps) Status(ctx context.Context, d Deployment) (*edge.WorkerStatus, error) {
	return o.worker(d).Status(ctx, "") // Bearer is set; no password login needed
}

func (o *liveOps) GetConfig(ctx context.Context, d Deployment) (map[string]any, error) {
	return o.worker(d).GetConfigRaw(ctx)
}

func (o *liveOps) PutConfig(ctx context.Context, d Deployment, cfg map[string]any) (map[string]any, error) {
	return o.worker(d).PutConfigRaw(ctx, cfg)
}

func (o *liveOps) RefreshCleanIPs(ctx context.Context, d Deployment) (*edge.CleanIPStore, error) {
	return o.worker(d).RefreshCleanIPs(ctx)
}

func (o *liveOps) ProbeCleanIP(ctx context.Context, d Deployment, target string) (*edge.CleanIPProbe, error) {
	return o.worker(d).ProbeCleanIP(ctx, target)
}

func (o *liveOps) RefreshExternal(ctx context.Context, d Deployment) (int, error) {
	return o.worker(d).RefreshExternal(ctx)
}

func (o *liveOps) RotatePath(ctx context.Context, d Deployment) (string, error) {
	return o.worker(d).RotatePath(ctx, "") // Bearer is set
}

func (o *liveOps) Warp(ctx context.Context, d Deployment) (int, error) {
	// Registration must run here on the bot host (a Worker cannot reach
	// Cloudflare's WARP API), then the accounts are pushed into the Worker.
	accounts, err := edge.RegisterWarpAccounts(ctx, nil)
	if err != nil {
		return 0, err
	}
	summaries, err := o.worker(d).StoreWarp(ctx, accounts)
	if err != nil {
		return 0, err
	}
	return len(summaries), nil
}

func (o *liveOps) WarpConf(ctx context.Context, d Deployment) (string, string, error) {
	return o.worker(d).WarpConf(ctx)
}
