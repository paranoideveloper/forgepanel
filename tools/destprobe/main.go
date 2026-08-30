package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/forgepanel/forgepanel/internal/realityprobe"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	for _, d := range os.Args[1:] {
		r := realityprobe.Probe(ctx, d)
		verdict := "USABLE"
		if !r.Usable {
			verdict = "REJECT"
		}
		fmt.Printf("%-24s %s  tls13=%v h2=%v chain=%-5d  %s\n",
			r.Dest, verdict, r.TLS13, r.ALPNH2, r.ChainBytes, r.Why)
	}
}
