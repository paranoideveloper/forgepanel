package upstream

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The installer is the only part of this package that speaks HTTP, so every test
// below stands a whole GitHub release up in memory — the latest-release API
// document, the .tar.gz asset and the SHA256SUMS.txt that pins it — and points
// the package's own client at it. Nothing here touches the real github.com.

// rewriteHost sends every request to a local test server while leaving the path
// intact, which is what makes the absolute URLs Descriptor builds testable.
type rewriteHost struct{ target *url.URL }

func (rt rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host, out.Host = rt.target.Scheme, rt.target.Host, rt.target.Host
	return http.DefaultTransport.RoundTrip(out)
}

// errTransport fails every request, standing in for an unreachable GitHub.
type errTransport struct{ err error }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// pinClient swaps the package HTTP client for the duration of one test.
func pinClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	prev := httpClient
	httpClient = &http.Client{Timeout: 30 * time.Second, Transport: rt}
	t.Cleanup(func() { httpClient = prev })
}

// serveRelease starts a test server and routes the package client at it.
func serveRelease(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	target, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	pinClient(t, rewriteHost{target: target})
	return ts
}

// tarEntry is one member of an in-memory archive.
type tarEntry struct {
	name string
	body string
	typ  byte
}

// buildTarGz assembles a gzip+tar archive in memory, so the extractor is
// exercised on bytes the test fully controls, including hostile ones.
func buildTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: typ}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gzipBytes wraps arbitrary bytes in a valid gzip stream (used to build an
// archive whose gzip layer is fine but whose tar layer is garbage).
func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// release is an in-memory GitHub release for one descriptor. Fields are public
// to the test so a case can corrupt exactly one of them.
type release struct {
	d       Descriptor
	arch    string
	tag     string
	asset   string // "<Project>_Server_Linux_<ARCH>.tar.gz"
	exeName string
	archive []byte
	sums    string

	apiStatus   int    // status for the latest-release API (0 = 200)
	apiBody     string // raw body for the latest-release API ("" = a valid document)
	assetStatus int    // status for asset downloads (0 = 200)
	omitSums    bool   // serve 404 for SHA256SUMS.txt
}

func newRelease(t *testing.T, adapter, tag string) *release {
	t.Helper()
	d, err := Lookup(adapter)
	if err != nil {
		t.Fatal(err)
	}
	arch, err := HostArch()
	if err != nil {
		t.Skipf("no release asset naming for this host: %v", err)
	}
	r := &release{d: d, arch: arch, tag: tag}
	r.asset = d.ServerAsset(arch) + ".tar.gz"
	r.exeName = d.ExeGlobPrefix(arch) + tag
	r.archive = buildTarGz(t,
		tarEntry{name: "README.md", body: "# not the executable\n"},
		tarEntry{name: "docs/", typ: tar.TypeDir},
		// A tar-slip attempt: the extractor must refuse it outright rather than
		// write "evil" anywhere.
		tarEntry{name: "../evil", body: "pwned"},
		tarEntry{name: r.exeName, body: "#!/bin/sh\nexit 0\n"},
	)
	r.sums = r.sumsFor(r.archive)
	return r
}

func (r *release) sumsFor(archive []byte) string {
	sum := sha256.Sum256(archive)
	return "0000000000000000000000000000000000000000000000000000000000000000  OtherFile.tar.gz\n" +
		hex.EncodeToString(sum[:]) + "  *" + r.asset + "\n"
}

func (r *release) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+r.d.Owner+"/"+r.d.Repo+"/releases/latest",
		func(w http.ResponseWriter, _ *http.Request) {
			if r.apiStatus != 0 {
				w.WriteHeader(r.apiStatus)
				return
			}
			body := r.apiBody
			if body == "" {
				body = fmt.Sprintf(`{"tag_name":%q}`, r.tag)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		})
	base := "/" + r.d.Owner + "/" + r.d.Repo + "/releases/download/" + r.tag + "/"
	mux.HandleFunc(base+r.asset, func(w http.ResponseWriter, _ *http.Request) {
		if r.assetStatus != 0 {
			w.WriteHeader(r.assetStatus)
			return
		}
		w.Write(r.archive)
	})
	mux.HandleFunc(base+"SHA256SUMS.txt", func(w http.ResponseWriter, _ *http.Request) {
		if r.omitSums {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, r.sums)
	})
	return mux
}

// TestInstallerEndToEnd drives the whole §4a path — resolve the latest tag,
// download, verify the published digest, extract, cache — against an in-memory
// release, and then proves the second call never touches the network again.
func TestInstallerEndToEnd(t *testing.T) {
	rel := newRelease(t, AdapterCottenDNS, "v2026.07.22.231403-a360409")
	serveRelease(t, rel.handler())

	data := t.TempDir()
	inst := NewInstaller(data)
	if want := filepath.Join(data, "bin", "forgedns"); inst.Root != want {
		t.Fatalf("installer root = %q, want %q", inst.Root, want)
	}

	// An empty tag must resolve the latest release rather than guess one.
	in, err := inst.Ensure(rel.d, "")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if in.Tag != rel.tag || in.Adapter != rel.d.Adapter || in.Asset != rel.asset {
		t.Fatalf("install = %+v", in)
	}
	if want := inst.dir(rel.d, rel.tag); in.Dir != want {
		t.Fatalf("install dir = %q, want %q", in.Dir, want)
	}
	if in.Exe != filepath.Join(in.Dir, rel.exeName) {
		t.Fatalf("exe = %q, want %q", in.Exe, filepath.Join(in.Dir, rel.exeName))
	}
	sum := sha256.Sum256(rel.archive)
	if in.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("recorded digest %q does not match the archive", in.SHA256)
	}
	fi, err := os.Stat(in.Exe)
	if err != nil {
		t.Fatalf("extracted exe: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("exe mode = %v, want 0755 — the supervisor has to be able to run it", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(in.Dir, "install.json")); err != nil {
		t.Fatalf("install.json was not written: %v", err)
	}
	// The tar-slip entry must not have landed anywhere.
	for _, p := range []string{filepath.Join(in.Dir, "evil"), filepath.Join(filepath.Dir(in.Dir), "evil")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("tar-slip entry escaped into %s", p)
		}
	}

	// Second call: the in-process memo answers without any HTTP at all, which is
	// proved by cutting the network first.
	pinClient(t, errTransport{err: errors.New("no network allowed")})
	again, err := inst.Ensure(rel.d, rel.tag)
	if err != nil {
		t.Fatalf("cached Ensure went to the network: %v", err)
	}
	if again.Exe != in.Exe {
		t.Fatalf("cached install differs: %q vs %q", again.Exe, in.Exe)
	}

	// A fresh installer over the same root must rehydrate from install.json.
	cold := NewInstaller(data)
	got, ok := cold.Lookup(rel.d, rel.tag)
	if !ok || got.Exe != in.Exe {
		t.Fatalf("cold Lookup = %+v, %v", got, ok)
	}
	// ...and answer the second time from the memo it just filled.
	if again, ok := cold.Lookup(rel.d, rel.tag); !ok || again.Exe != in.Exe {
		t.Fatalf("memoised Lookup = %+v, %v", again, ok)
	}
}

// TestInstallerLookupMisses covers every reason a cache entry is not usable.
func TestInstallerLookupMisses(t *testing.T) {
	d, _ := Lookup(AdapterStormDNS)
	data := t.TempDir()
	inst := NewInstaller(data)

	if _, ok := inst.Lookup(d, ""); ok {
		t.Error("an empty tag can never name a cached install")
	}
	if _, ok := inst.Lookup(d, "v1"); ok {
		t.Error("a tag with no install.json must miss")
	}

	write := func(tag, body string) {
		dir := inst.dir(d, tag)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "install.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("v-bad-json", "{not json")
	if _, ok := inst.Lookup(d, "v-bad-json"); ok {
		t.Error("a corrupt install.json must miss, not panic")
	}
	write("v-missing-exe", `{"exe":"/nonexistent/forgedns-test-binary"}`)
	if _, ok := inst.Lookup(d, "v-missing-exe"); ok {
		t.Error("an install.json pointing at a vanished binary must miss")
	}
	// Present but not executable: the supervisor could not run it, so it is not
	// a usable install.
	dir := inst.dir(d, "v-not-exec")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	write("v-not-exec", fmt.Sprintf(`{"exe":%q}`, plain))
	if _, ok := inst.Lookup(d, "v-not-exec"); ok {
		t.Error("a non-executable file must not count as an install")
	}
}

// TestLatestTag covers the release-resolution step and each way it can fail.
func TestLatestTag(t *testing.T) {
	rel := newRelease(t, AdapterMasterDNS, "v9.9.9")
	serveRelease(t, rel.handler())
	inst := NewInstaller(t.TempDir())

	tag, err := inst.LatestTag(rel.d)
	if err != nil || tag != rel.tag {
		t.Fatalf("LatestTag = %q, %v", tag, err)
	}

	// An optional token only raises the rate limit; the code path that sets the
	// header must still work when one is present.
	t.Setenv("GITHUB_TOKEN", "test-token")
	if tag, err := inst.LatestTag(rel.d); err != nil || tag != rel.tag {
		t.Fatalf("LatestTag with a token = %q, %v", tag, err)
	}

	rel.apiStatus = http.StatusForbidden
	if _, err := inst.LatestTag(rel.d); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("rate-limited API should surface its status, got %v", err)
	}

	rel.apiStatus, rel.apiBody = 0, "{this is not json"
	if _, err := inst.LatestTag(rel.d); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("undecodable release document should be reported, got %v", err)
	}

	rel.apiBody = `{"tag_name":""}`
	if _, err := inst.LatestTag(rel.d); err == nil || !strings.Contains(err.Error(), "no tag_name") {
		t.Fatalf("a release with no tag must be refused, got %v", err)
	}

	pinClient(t, errTransport{err: errors.New("dial refused")})
	if _, err := inst.LatestTag(rel.d); err == nil || !strings.Contains(err.Error(), "latest release") {
		t.Fatalf("an unreachable API should be reported with context, got %v", err)
	}
}

// TestEnsureRefusesUnverifiedArchives is the §4a step-2 guard: nothing is
// installed unless the published SHA256SUMS.txt agrees with the bytes.
func TestEnsureRefusesUnverifiedArchives(t *testing.T) {
	t.Run("digest mismatch", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.sums = strings.Repeat("a", 64) + "  " + rel.asset + "\n"
		serveRelease(t, rel.handler())
		_, err := NewInstaller(t.TempDir()).Ensure(rel.d, rel.tag)
		if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Fatalf("a tampered archive must be refused, got %v", err)
		}
	})

	t.Run("asset not listed", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.sums = strings.Repeat("b", 64) + "  SomethingElse.tar.gz\n"
		serveRelease(t, rel.handler())
		_, err := NewInstaller(t.TempDir()).Ensure(rel.d, rel.tag)
		if err == nil || !strings.Contains(err.Error(), "not listed") {
			t.Fatalf("an unlisted asset must be refused, got %v", err)
		}
	})

	t.Run("no sums file", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.omitSums = true
		serveRelease(t, rel.handler())
		_, err := NewInstaller(t.TempDir()).Ensure(rel.d, rel.tag)
		if err == nil || !strings.Contains(err.Error(), "SHA256SUMS.txt") {
			t.Fatalf("a release with nothing to verify against must be refused, got %v", err)
		}
	})

	t.Run("asset missing", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.assetStatus = http.StatusNotFound
		serveRelease(t, rel.handler())
		_, err := NewInstaller(t.TempDir()).Ensure(rel.d, rel.tag)
		if err == nil || !strings.Contains(err.Error(), "download") {
			t.Fatalf("a missing asset must be reported, got %v", err)
		}
	})

	t.Run("archive holds no executable", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.archive = buildTarGz(t, tarEntry{name: "README.md", body: "nothing runnable here"})
		rel.sums = rel.sumsFor(rel.archive)
		serveRelease(t, rel.handler())
		_, err := NewInstaller(t.TempDir()).Ensure(rel.d, rel.tag)
		if err == nil || !strings.Contains(err.Error(), "extract") {
			t.Fatalf("an archive with no server binary must be refused, got %v", err)
		}
	})

	t.Run("latest resolution fails", func(t *testing.T) {
		rel := newRelease(t, AdapterCottenDNS, "v1")
		rel.apiStatus = http.StatusInternalServerError
		serveRelease(t, rel.handler())
		if _, err := NewInstaller(t.TempDir()).Ensure(rel.d, ""); err == nil {
			t.Fatal("Ensure must fail when the latest tag cannot be resolved")
		}
	})
}

// TestExtractTarGz pins the extractor's two contracts: the tagged executable is
// found by prefix and made runnable, and nothing may escape the target directory.
func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	const prefix = "CottenDns_Server_Linux_AMD64_"
	archive := buildTarGz(t,
		tarEntry{name: "notes.txt", body: "plain file"},
		tarEntry{name: "sub/", typ: tar.TypeDir},
		tarEntry{name: "link", typ: tar.TypeSymlink},
		tarEntry{name: "../../evil", body: "escape attempt"},
		tarEntry{name: "..", body: "dot dot"},
		tarEntry{name: prefix + "v2026.01.01", body: "#!/bin/sh\nexit 0\n"},
	)
	exe, err := extractTarGz(archive, dir, prefix)
	if err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	if exe != filepath.Join(dir, prefix+"v2026.01.01") {
		t.Fatalf("exe = %q", exe)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("exe mode = %v, want 0755", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("ordinary file was not extracted: %v", err)
	}
	for _, p := range []string{
		filepath.Join(dir, "evil"),
		filepath.Join(filepath.Dir(dir), "evil"),
		filepath.Join(dir, "sub"),
		filepath.Join(dir, "link"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s should not have been created", p)
		}
	}
}

func TestExtractTarGzRejectsBadArchives(t *testing.T) {
	dir := t.TempDir()
	if _, err := extractTarGz([]byte("not gzip at all"), dir, "x"); err == nil {
		t.Error("a non-gzip body must be refused")
	}
	if _, err := extractTarGz(gzipBytes(t, []byte("gzip fine, tar garbage")), dir, "x"); err == nil {
		t.Error("a corrupt tar stream must be refused")
	}
	archive := buildTarGz(t, tarEntry{name: "README.md", body: "hi"})
	if _, err := extractTarGz(archive, dir, "Server_"); err == nil ||
		!strings.Contains(err.Error(), "no Server_* executable") {
		t.Errorf("missing executable must be named in the error, got %v", err)
	}
}

// TestGetBoundsAndStatus covers the small download helper directly: a normal
// body, a non-200 and the cap that refuses a hostile response.
func TestGetBoundsAndStatus(t *testing.T) {
	var path string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("release bytes"))
		case "/huge":
			// Deliberately overruns the cap; get() must stop reading at it.
			chunk := bytes.Repeat([]byte("x"), 1<<20)
			for i := 0; i < (maxArchiveBytes>>20)+2; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	body, err := get(ts.URL + "/ok")
	if err != nil || string(body) != "release bytes" {
		t.Fatalf("get = %q, %v", body, err)
	}
	if path != "/ok" {
		t.Fatalf("server saw %q", path)
	}

	if _, err := get(ts.URL + "/missing"); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("a non-200 must be an error naming the status, got %v", err)
	}

	if _, err := get("://not a url"); err == nil {
		t.Error("an unparseable URL must be an error, not a request")
	}

	if testing.Short() {
		t.Skip("skipping the 64 MiB cap check in short mode")
	}
	capped, err := get(ts.URL + "/huge")
	if err != nil {
		t.Fatalf("oversized body: %v", err)
	}
	if len(capped) != maxArchiveBytes {
		t.Fatalf("read %d bytes, want the %d-byte cap", len(capped), maxArchiveBytes)
	}
}

// TestLookupSumFormats covers the sha256sum listing dialects the releases use.
func TestLookupSumFormats(t *testing.T) {
	listing := "\n" +
		"   \n" +
		"noise\n" + // fewer than two fields: skipped
		"aaa  ./nested/path/Server_AMD64.tar.gz\n" +
		"bbb  *Server_ARM64.tar.gz\n"
	for file, want := range map[string]string{
		"Server_AMD64.tar.gz": "aaa",
		"Server_ARM64.tar.gz": "bbb",
	} {
		got, ok := lookupSum(listing, file)
		if !ok || got != want {
			t.Errorf("lookupSum(%q) = %q, %v; want %q", file, got, ok, want)
		}
	}
	if _, ok := lookupSum(listing, "noise"); ok {
		t.Error("a short line must never be read as a digest")
	}
	if _, ok := lookupSum("", "anything"); ok {
		t.Error("an empty listing pins nothing")
	}
}
