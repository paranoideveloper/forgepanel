package dns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// PoolConfig configures a rotation pool.
type PoolConfig struct {
	// Name identifies the pool in storage.
	Name string
	// Provider is used to create replacement records. Nil disables healing.
	Provider Provider
	// ZoneRef is where replacements are written.
	ZoneRef string
	// Domain is the parent for generated replacement names.
	Domain string
	// Template is the naming pattern for replacements.
	Template string
	// Vars feeds the naming template.
	Vars TemplateVars
	// Target is the record content for replacements (the origin IP, or a CNAME
	// target).
	Target string
	// RecordType is the replacement record type. Zero means A.
	RecordType RecordType
	// Proxied is the replacement record's proxy flag.
	Proxied bool
	// TTL for replacement records.
	TTL int
	// MinHealthy is the number of usable entries the pool maintains.
	MinHealthy int
	// FailureThreshold is the consecutive failures before retirement. Zero
	// means 3 — one blip should not burn a name.
	FailureThreshold int
	// DeleteRetired removes the DNS record when an entry retires.
	DeleteRetired bool
	// Prober health-checks entries. Nil means TLSProber on 443.
	Prober Prober
	// Concurrency bounds simultaneous probes. Zero means 8.
	Concurrency int
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Pool is a health-checked, self-healing set of domains. Clients are handed
// Active entries; the pool retires names that stop working and mints fresh
// subdomains to replace them, which is what keeps a blocked hostname from
// becoming an outage.
type Pool struct {
	cfg  PoolConfig
	repo PoolRepo
	mu   sync.Mutex
}

// NewPool builds a pool over a repository.
func NewPool(cfg PoolConfig, repo PoolRepo) (*Pool, error) {
	if repo == nil {
		return nil, &Error{Op: "new-pool", Kind: KindValidation,
			Message: "no pool repository was supplied", Remediation: "pass Deps.Pools"}
	}
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = "default"
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.RecordType == "" {
		cfg.RecordType = TypeA
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Pool{cfg: cfg, repo: repo}, nil
}

// Name returns the pool name.
func (p *Pool) Name() string { return p.cfg.Name }

// Entries returns every stored entry, best first.
func (p *Pool) Entries() ([]PoolEntry, error) {
	entries, err := p.repo.ListPoolEntries(p.cfg.Name)
	if err != nil {
		return nil, wrapRepoError("list-pool", err)
	}
	sortEntries(entries)
	return entries, nil
}

// Active returns the entries clients should be handed, best first.
func (p *Pool) Active() ([]PoolEntry, error) {
	entries, err := p.Entries()
	if err != nil {
		return nil, err
	}
	out := make([]PoolEntry, 0, len(entries))
	for _, e := range entries {
		if e.Healthy() {
			out = append(out, e)
		}
	}
	return out, nil
}

// sortEntries ranks healthy before retired, then by latency, then by name for
// a stable order.
func sortEntries(entries []PoolEntry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Healthy() != b.Healthy() {
			return a.Healthy()
		}
		if a.Failures != b.Failures {
			return a.Failures < b.Failures
		}
		if a.LatencyMs != b.LatencyMs {
			// An unchecked entry (0ms) sorts after checked ones.
			if a.LatencyMs == 0 {
				return false
			}
			if b.LatencyMs == 0 {
				return true
			}
			return a.LatencyMs < b.LatencyMs
		}
		return a.Domain < b.Domain
	})
}

// Add registers an existing domain in the pool.
func (p *Pool) Add(entry PoolEntry) error {
	if err := ValidateFQDN(entry.Domain); err != nil {
		return err
	}
	entry.Domain = NormalizeDomain(entry.Domain)
	if entry.State == "" {
		entry.State = PoolActive
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = p.cfg.Now().UTC()
	}
	if err := p.repo.PutPoolEntry(p.cfg.Name, entry); err != nil {
		return wrapRepoError("add-pool-entry", err)
	}
	return nil
}

// Remove drops an entry from the pool without touching DNS.
func (p *Pool) Remove(domain string) error {
	if err := p.repo.DeletePoolEntry(p.cfg.Name, NormalizeDomain(domain)); err != nil {
		return wrapRepoError("remove-pool-entry", err)
	}
	return nil
}

// PoolReport is the outcome of a health sweep.
type PoolReport struct {
	Pool      string      `json:"pool"`
	Checked   int         `json:"checked"`
	Healthy   int         `json:"healthy"`
	Retired   []string    `json:"retired,omitempty"`
	Recovered []string    `json:"recovered,omitempty"`
	Entries   []PoolEntry `json:"entries"`
	CheckedAt string      `json:"checked_at"`
}

// Check probes every entry and updates its state. It returns the sweep result;
// a probe failure is data, not an error.
func (p *Pool) Check(ctx context.Context) (*PoolReport, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.check(ctx)
}

func (p *Pool) check(ctx context.Context) (*PoolReport, error) {
	entries, err := p.Entries()
	if err != nil {
		return nil, err
	}
	prober := p.cfg.Prober
	if prober == nil {
		prober = TLSProber{}
	}
	concurrency := p.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > len(entries) && len(entries) > 0 {
		concurrency = len(entries)
	}

	results := make([]ProbeResult, len(entries))
	if len(entries) > 0 {
		var wg sync.WaitGroup
		jobs := make(chan int)
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					results[i] = prober.Probe(ctx, entries[i].Domain)
				}
			}()
		}
		for i := range entries {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}

	now := p.cfg.Now().UTC()
	report := &PoolReport{Pool: p.cfg.Name, Checked: len(entries), CheckedAt: now.Format(time.RFC3339)}
	for i := range entries {
		e := &entries[i]
		res := results[i]
		e.Checks++
		e.CheckedAt = now
		wasRetired := e.State == PoolRetired
		if res.OK {
			if wasRetired {
				report.Recovered = append(report.Recovered, e.Domain)
			}
			e.Failures = 0
			e.State = PoolActive
			e.LatencyMs = res.Latency.Milliseconds()
			e.LastError = ""
		} else {
			e.Failures++
			e.LastError = res.Detail
			if e.Failures >= p.cfg.FailureThreshold {
				e.State = PoolRetired
				if !wasRetired {
					report.Retired = append(report.Retired, e.Domain)
				}
			} else {
				e.State = PoolDegraded
			}
		}
		if e.Healthy() {
			report.Healthy++
		}
		if err := p.repo.PutPoolEntry(p.cfg.Name, *e); err != nil {
			return nil, wrapRepoError("check-pool", err)
		}
	}
	sortEntries(entries)
	report.Entries = entries
	return report, nil
}

// RotateResult reports a healing pass.
type RotateResult struct {
	Pool string `json:"pool"`
	// Report is the health sweep the rotation acted on.
	Report *PoolReport `json:"report"`
	// Added lists fresh domains created to restore MinHealthy.
	Added []PoolEntry `json:"added,omitempty"`
	// Deleted lists retired records removed from DNS.
	Deleted []string `json:"deleted,omitempty"`
	// Shortfall is how many entries the pool is still missing, if replacements
	// could not be created.
	Shortfall int    `json:"shortfall,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Rotate health-checks the pool, retires dead entries and mints fresh
// subdomains until MinHealthy usable entries exist again.
func (p *Pool) Rotate(ctx context.Context) (*RotateResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	report, err := p.check(ctx)
	if err != nil {
		return nil, err
	}
	out := &RotateResult{Pool: p.cfg.Name, Report: report}

	if p.cfg.DeleteRetired && p.cfg.Provider != nil {
		for _, e := range report.Entries {
			if e.State != PoolRetired || e.RecordID == "" {
				continue
			}
			zone := e.Zone
			if zone == "" {
				zone = p.cfg.ZoneRef
			}
			if err := p.cfg.Provider.DeleteRecord(ctx, zone, e.RecordID); err != nil && !IsNotFound(err) {
				out.Note = strings.TrimSpace(out.Note + " could not delete retired record " + e.Domain + ": " + err.Error())
				continue
			}
			if err := p.repo.DeletePoolEntry(p.cfg.Name, e.Domain); err != nil {
				return nil, wrapRepoError("rotate-pool", err)
			}
			out.Deleted = append(out.Deleted, e.Domain)
		}
	}

	need := p.cfg.MinHealthy - report.Healthy
	if need <= 0 {
		return out, nil
	}
	if p.cfg.Provider == nil {
		out.Shortfall = need
		out.Note = fmt.Sprintf("the pool is %d entr%s below its minimum of %d, but no DNS provider is configured so replacements cannot be created automatically. Register a credential for the zone, or add domains manually.",
			need, plural(need, "y", "ies"), p.cfg.MinHealthy)
		return out, nil
	}
	if strings.TrimSpace(p.cfg.Domain) == "" || strings.TrimSpace(p.cfg.Target) == "" {
		out.Shortfall = need
		out.Note = "replacements need both a parent domain and a target; set PoolConfig.Domain and PoolConfig.Target."
		return out, nil
	}

	tpl := NewNameTemplate(p.cfg.Template)
	existing := map[string]bool{}
	for _, e := range report.Entries {
		existing[e.Domain] = true
	}
	now := p.cfg.Now().UTC()
	for created := 0; created < need; {
		names, err := tpl.GenerateNames(p.cfg.Domain, need-created, p.cfg.Vars)
		if err != nil {
			out.Shortfall = need - created
			out.Note = err.Error()
			return out, nil
		}
		progress := false
		for _, name := range names {
			if existing[name] {
				continue
			}
			rec := Record{
				Type: p.cfg.RecordType, Name: name, Content: p.cfg.Target,
				TTL: p.cfg.TTL, Proxied: p.cfg.Proxied,
				Comment: "forgepanel rotation pool " + p.cfg.Name,
			}
			res, err := EnsureRecord(ctx, p.cfg.Provider, p.cfg.ZoneRef, rec)
			if err != nil {
				out.Shortfall = need - created
				if e, ok := AsError(err); ok {
					out.Note = e.Message + " — " + e.Remediation
				} else {
					out.Note = err.Error()
				}
				return out, nil
			}
			entry := PoolEntry{
				Domain: name, Zone: p.cfg.ZoneRef, RecordID: res.Record.ID,
				Provider: p.cfg.Provider.Name(), Target: p.cfg.Target,
				Proxied: p.cfg.Proxied, State: PoolActive, CreatedAt: now,
			}
			if err := p.repo.PutPoolEntry(p.cfg.Name, entry); err != nil {
				return nil, wrapRepoError("rotate-pool", err)
			}
			existing[name] = true
			out.Added = append(out.Added, entry)
			created++
			progress = true
			if created >= need {
				break
			}
		}
		if !progress {
			out.Shortfall = need - created
			out.Note = "the naming template kept producing names already in the pool; add {rand} so replacements are unique."
			return out, nil
		}
	}
	return out, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
