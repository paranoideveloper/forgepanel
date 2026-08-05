package main

import (
	"fmt"

	fpversion "github.com/forgepanel/forgepanel/internal/version"
)

// version is stamped at link time with -X main.version=<v>. Every packaging
// path passes the same value (Makefile, Dockerfile build arg, GoReleaser and
// nfpm), so `forgectl version` is what a package smoke test asserts against.
// The default matters: a hand-built binary must say "dev", never claim a
// release version it is not.
//
// It is mirrored into internal/version so forgectl and forgepanel render the
// same identity from the same code, and CI can compare them.
var version = "dev"

func init() {
	if version != "dev" {
		fpversion.Version = version
	}
}

func cmdVersion([]string) error {
	fmt.Println(fpversion.String("forgectl"))
	return nil
}
