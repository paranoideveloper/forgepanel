//go:build ignore

package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/forgepanel/forgepanel/internal/diag"
)

func main() {
	codes := make([]string, 0, len(diag.Catalogue))
	for c := range diag.Catalogue {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	f, _ := os.Create("docs/DIAGNOSTICS.md")
	defer f.Close()
	fmt.Fprintln(f, "# ForgePanel Diagnostics Catalogue")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "Every finding the Validation & Proof engine (§3) can raise has a stable code")
	fmt.Fprintln(f, "so messages are searchable. Each carries English + Farsi text, why it matters,")
	fmt.Fprintln(f, "and the exact fix; some have a one-click Fix It action.")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "| Code | Severity | Meaning (EN) | معنی (FA) | Why | Fix | Fix action |")
	fmt.Fprintln(f, "|------|----------|--------------|-----------|-----|-----|------------|")
	for _, c := range codes {
		e := diag.Catalogue[c]
		act := e.Action
		if act == "" {
			act = "—"
		}
		fmt.Fprintf(f, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			c, e.Severity, e.TitleEN, e.TitleFA, e.Why, e.Fix, act)
	}
}
