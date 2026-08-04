package main

import (
	"fmt"
	"runtime"
)

// version is stamped at link time with -X main.version=<v>. Every packaging
// path passes the same value (Makefile, Dockerfile build arg, GoReleaser and
// nfpm), so `forgectl version` is what a package smoke test asserts against.
// The default matters: a hand-built binary must say "dev", never claim a
// release version it is not.
var version = "dev"

func cmdVersion([]string) error {
	fmt.Printf("forgectl %s %s/%s (%s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return nil
}
