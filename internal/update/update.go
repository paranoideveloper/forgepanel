// Package update is the panel's own release lookup and staging step.
//
// It exists because the only thing in this tree that knew how to update the
// panel was `forgectl update`, which is pinned to /releases/latest — so an
// operator running a release candidate had no way to see the next one, and
// nobody driving the panel from a browser had any way to see an update at all.
//
// The split of responsibility is deliberate and is enforced by the unit file
// rather than by taste: packaging/systemd/forgepanel.service sets
// ProtectSystem=full with ReadWritePaths limited to the data dir, so this
// process can download, verify and RUN a candidate binary under <dataDir>, and
// cannot write /usr/local/bin. Checking and staging therefore live here;
// applying stays with the installer, and the API says so in its own response.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/netegress"
)

// Channel selects which releases the panel offers.
type Channel string

const (
	ChannelStable     Channel = "stable"
	ChannelPrerelease Channel = "prerelease"
)

// Repo is the upstream this panel updates from. It matches the repository
// cmd/forgectl/local.go's releaseAPI points at; the two must not drift.
const Repo = "paranoideveloper/forgepanel"

// GitHubAPIBase is overridable so the check can be tested without the network,
// the same escape hatch internal/edge/worker_api.go uses.
var GitHubAPIBase = "https://api.github.com"

// checkTimeout bounds a metadata lookup. It is advisory: a panel on a filtered
// link must not hang a page waiting for GitHub.
const checkTimeout = 20 * time.Second

// Asset is one file attached to a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is what the panel reports about the newest release on a channel.
//
// Assets is carried for Stage and not serialized: the browser has no use for
// download URLs it is not allowed to fetch, and the panel is the thing that
// verifies them.
type Release struct {
	Tag             string  `json:"tag"`
	Prerelease      bool    `json:"prerelease"`
	Notes           string  `json:"notes,omitempty"`
	PublishedAt     string  `json:"published_at,omitempty"`
	HTMLURL         string  `json:"html_url,omitempty"`
	Assets          []Asset `json:"-"`
	Current         string  `json:"current"`
	Latest          string  `json:"latest"`
	UpdateAvailable bool    `json:"update_available"`
	Channel         Channel `json:"channel"`
}

// ghRelease is the subset of GitHub's release object this package reads.
type ghRelease struct {
	TagName     string  `json:"tag_name"`
	Prerelease  bool    `json:"prerelease"`
	Body        string  `json:"body"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Assets      []Asset `json:"assets"`
}

// Check reports the newest release on ch, relative to current.
//
// The two channels are two different endpoints, not one endpoint filtered:
// /releases/latest cannot return a prerelease by definition, which is exactly
// why forgectl has never been able to offer one.
func Check(ctx context.Context, repo string, ch Channel, current string) (*Release, error) {
	if repo == "" {
		repo = Repo
	}
	base := strings.TrimSuffix(GitHubAPIBase, "/") + "/repos/" + repo + "/releases"

	var url string
	switch ch {
	case ChannelStable:
		url = base + "/latest"
	case ChannelPrerelease:
		// Newest first, prereleases included; the first entry is the answer.
		url = base + "?per_page=20"
	default:
		return nil, apierr.Validation("update-check",
			fmt.Sprintf("unknown update channel %q", string(ch)),
			"choose either \"stable\" or \"prerelease\".")
	}

	raw, err := get(ctx, url, netegress.Client(checkTimeout), 4<<20)
	if err != nil {
		return nil, err
	}

	var gh ghRelease
	if ch == ChannelPrerelease {
		var list []ghRelease
		if derr := json.Unmarshal(raw, &list); derr != nil {
			return nil, decodeFailure(derr)
		}
		if len(list) == 0 {
			return nil, &apierr.Error{Op: "update-check", Kind: apierr.KindServer,
				Message: "the " + repo + " releases list is empty"}
		}
		gh = list[0]
	} else if derr := json.Unmarshal(raw, &gh); derr != nil {
		return nil, decodeFailure(derr)
	}

	// The tag keeps its leading "v". internal/version's Version is stamped with
	// GoReleaser's {{ .Tag }} — with the v — and install.sh greps --version
	// output for that same raw tag. Trimming it here (as internal/edge does for
	// the Worker, which has no such stamping) would make UpdateAvailable
	// permanently true and would make Stage's smoke test unmatchable.
	rel := &Release{
		Tag: gh.TagName, Prerelease: gh.Prerelease, Notes: gh.Body,
		PublishedAt: gh.PublishedAt, HTMLURL: gh.HTMLURL, Assets: gh.Assets,
		Current: current, Latest: gh.TagName, Channel: ch,
	}
	rel.UpdateAvailable = rel.Latest != "" && rel.Latest != current
	return rel, nil
}

// get performs one GET and returns the body, translating every failure into the
// panel's error envelope so the handler above needs no switch of its own.
func get(ctx context.Context, url string, client *http.Client, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, apierr.Validation("update-check", err.Error(), "")
	}
	req.Header.Set("User-Agent", "ForgePanel")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, &apierr.Error{Op: "update-check", Kind: apierr.KindNetwork,
			Message:     "could not reach the release API: " + err.Error(),
			Remediation: "this host may have no direct outbound HTTPS; set an egress proxy under Settings → Egress.",
			Cause:       err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode != http.StatusOK {
		return nil, &apierr.Error{Op: "update-check", Kind: apierr.KindServer, Status: resp.StatusCode,
			Message: "the release API returned " + resp.Status + ": " + truncate(string(raw), 200)}
	}
	return raw, nil
}

func decodeFailure(err error) error {
	return &apierr.Error{Op: "update-check", Kind: apierr.KindServer,
		Message: "the release API returned something that is not a release: " + err.Error(), Cause: err}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
