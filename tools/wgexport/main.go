package main

// Render the panel's native WireGuard / AmneziaWG client config from a stored
// node, so the exported text can be checked against what a client actually
// parses rather than against a URI that no client accepts.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	host := os.Args[2]
	var n model.Node
	if err := json.Unmarshal(raw, &n); err != nil {
		panic(err)
	}
	n.Normalize()

	var conf string
	switch n.Protocol {
	case model.ProtoWireGuard:
		conf, err = export.WireGuardConf(&n, host)
	case model.ProtoAmneziaWG:
		conf, err = export.AmneziaWGConf(&n, host)
	default:
		fmt.Println("not a wireguard-family node:", n.Protocol)
		return
	}
	if err != nil {
		fmt.Println("EXPORT FAILED:", err)
		os.Exit(1)
	}
	fmt.Print(conf)

	// Also show what the URI exporter does with it, which is the thing Rasoul
	// says is useless for this protocol family.
	if u, uerr := export.URI(&n); uerr == nil {
		fmt.Printf("\n--- export.URI() for comparison ---\n%s\n", u)
	} else {
		fmt.Printf("\n--- export.URI() for comparison ---\n(refused: %v)\n", uerr)
	}
}
