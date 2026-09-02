package main

import "testing"

func TestForgnodeVersionFlag(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-v"}, {"version"}} {
		if !nodeVersionRequested(args) {
			t.Fatalf("version args not recognized: %v", args)
		}
	}
	if nodeVersionRequested([]string{"--version", "extra"}) {
		t.Fatal("version args accepted unexpected input")
	}
}
