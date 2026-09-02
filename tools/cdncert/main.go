package main

// Exercise the panel's OWN DNS-01 path against a real zone, so the preset's new
// certificate step is verified by the same functions it calls rather than by an
// external ACME client that proves nothing about this code.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/dns"
)

func main() {
	dataDir, host, token := os.Args[1], os.Args[2], os.Args[3]
	staging := len(os.Args) > 4 && os.Args[4] == "staging"

	// allow-any: this tool issues for exactly the host it is given.
	store := cert.NewStore(dataDir, staging, func(string) bool { return true })
	if cp, kp, ok := store.Materialize(host); ok {
		fmt.Printf("ALREADY PRESENT for %s\n  %s\n  %s\n", host, cp, kp)
		return
	}
	prov, err := dns.NewCloudflare(dns.Credentials{"api_token": token})
	if err != nil {
		fmt.Println("provider:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	fmt.Printf("issuing for %s (staging=%v)…\n", host, staging)
	if _, err := store.IssueDNS01(ctx, cert.DNS01Options{
		Solver:  &dns.ACMESolver{Provider: prov},
		Staging: staging,
		// Public resolvers: the host's caches the NXDOMAIN a previous attempt's
		// cleanup left behind, and then cannot see the new record.
		Lookup: func(c context.Context, fqdn string) ([]string, error) {
			return dns.NewResolver().LookupTXT(c, fqdn)
		},
	}, host); err != nil {
		fmt.Println("ISSUANCE FAILED:", err)
		os.Exit(1)
	}
	cp, kp, ok := store.Materialize(host)
	fmt.Printf("ISSUED. Materialize(%s) -> ok=%v\n  %s\n  %s\n", host, ok, cp, kp)
}
