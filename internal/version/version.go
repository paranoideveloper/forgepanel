// Package version carries the build identity every ForgePanel binary reports.
//
// The values are stamped at link time with -X. Every packaging path — the
// Makefile, the Dockerfile, GoReleaser and the release workflow — passes the
// same three, so a binary, a .deb and a container image built from one tag all
// report the same thing, and CI can assert they match rather than hoping.
//
// The defaults matter as much as the stamping: an unstamped build must say
// "dev" and never claim a release version it is not. Release CI verifies that a
// tagged artifact does NOT report "dev", which is what stops a mis-wired ldflags
// change shipping unidentifiable binaries.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	// Version is the release version, e.g. "v1.2.0". "dev" when unstamped.
	Version = "dev"
	// Commit is the source revision the artifact was built from.
	Commit = ""
	// Date is the RFC3339 build timestamp.
	Date = ""
)

// Info is the machine-readable build identity, surfaced by the API so an
// operator can confirm what is actually running without shelling in.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Get returns the build identity, falling back to the Go build info embedded by
// the toolchain when the commit was not stamped explicitly (a plain `go build`
// still knows its VCS revision).
func Get() Info {
	i := Info{Version: Version, Commit: Commit, Date: Date,
		Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if i.Commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					i.Commit = s.Value
				}
				if s.Key == "vcs.time" && i.Date == "" {
					i.Date = s.Value
				}
			}
		}
	}
	return i
}

// IsRelease reports whether this build carries a stamped release version, as
// opposed to a local or untagged build.
func IsRelease() bool { return Version != "" && Version != "dev" }

// String renders the one-line form used by --version and the startup banner.
func String(binary string) string {
	i := Get()
	s := fmt.Sprintf("%s %s %s/%s (%s)", binary, i.Version, i.OS, i.Arch, i.Go)
	if i.Commit != "" {
		c := i.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		s += " commit " + c
	}
	if i.Date != "" {
		s += " built " + i.Date
	}
	return s
}
