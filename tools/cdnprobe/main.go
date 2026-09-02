package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/forgepanel/forgepanel/internal/cdncheck"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	host := os.Args[1]
	for _, ps := range os.Args[2:] {
		p, _ := strconv.Atoi(ps)
		r := cdncheck.Check(ctx, host, p)
		state := "REACHED ORIGIN"
		if !r.Reached {
			state = "BLOCKED"
		}
		fmt.Printf("%s:%-5d %-15s status=%-4d %s\n", r.Host, r.Port, state, r.Status, r.Problem)
		if r.Fix != "" {
			fmt.Printf("   fix: %s\n", r.Fix)
		}
	}
}
