package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgepanel/forgepanel/internal/apierr"
)

func stubGitHub(t *testing.T) {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/repos/paranoideveloper/forgepanel/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","html_url":"https://example.invalid/1"}`))
		case "/repos/paranoideveloper/forgepanel/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0-rc1","prerelease":true},{"tag_name":"v1.0.0"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(gh.Close)
	old := GitHubAPIBase
	GitHubAPIBase = gh.URL
	t.Cleanup(func() { GitHubAPIBase = old })
}

func TestCheckPicksTheEndpointTheChannelImplies(t *testing.T) {
	stubGitHub(t)

	stable, err := Check(context.Background(), "", ChannelStable, "v1.0.0")
	if err != nil {
		t.Fatalf("stable: %v", err)
	}
	if stable.Latest != "v1.0.0" || stable.UpdateAvailable {
		t.Errorf("stable = {latest:%q available:%v}, want the current tag and no update",
			stable.Latest, stable.UpdateAvailable)
	}

	pre, err := Check(context.Background(), "", ChannelPrerelease, "v1.0.0")
	if err != nil {
		t.Fatalf("prerelease: %v", err)
	}
	if pre.Latest != "v2.0.0-rc1" || !pre.UpdateAvailable || !pre.Prerelease {
		t.Errorf("prerelease = %+v, want the rc tag flagged as an available prerelease", pre)
	}
}

// The tag keeps its "v". version.Version is stamped with {{ .Tag }} and the
// installer greps --version output for the raw tag, so trimming it here would
// make UpdateAvailable permanently true and break Stage's smoke test.
func TestCheckKeepsTheVPrefixSoTheComparisonMeansSomething(t *testing.T) {
	stubGitHub(t)
	rel, err := Check(context.Background(), "", ChannelStable, "v1.0.0")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rel.Latest != "v1.0.0" {
		t.Fatalf("latest = %q: the v was stripped, so no stamped build can ever match it", rel.Latest)
	}
}

func TestCheckRefusesAChannelItCannotResolve(t *testing.T) {
	stubGitHub(t)
	_, err := Check(context.Background(), "", Channel("nightly"), "v1.0.0")
	if err == nil {
		t.Fatal("Check accepted a channel with no release endpoint behind it")
	}
	if k := apierr.From(err).Kind; k != apierr.KindValidation {
		t.Errorf("kind = %q, want %q", k, apierr.KindValidation)
	}
}

func TestCheckReportsAnUpstreamRefusalAsTheServersFault(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer gh.Close()
	old := GitHubAPIBase
	GitHubAPIBase = gh.URL
	defer func() { GitHubAPIBase = old }()

	_, err := Check(context.Background(), "", ChannelStable, "v1.0.0")
	if err == nil {
		t.Fatal("Check treated a 403 as a successful lookup")
	}
	if k := apierr.From(err).Kind; k != apierr.KindServer {
		t.Errorf("kind = %q, want %q", k, apierr.KindServer)
	}
}
