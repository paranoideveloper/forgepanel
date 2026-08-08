package edge

import (
	_ "embed"
	"strings"
)

// embeddedBundle is the compiled ForgeEdge Worker (deploy/cloudflare/forgeedge/
// src → a single ESM module), baked into the panel binary so a deploy needs no
// external build step or checked-out worker source. Regenerate after changing
// the Worker source with `make edge-bundle`.
//
//go:embed assets/forgeedge.worker.js
var embeddedBundle string

// Bundle returns the embedded ForgeEdge Worker bundle.
func Bundle() []byte { return []byte(embeddedBundle) }

// HasBundle reports whether a usable bundle is compiled in (a placeholder/empty
// asset would fail a deploy, so callers gate on this before defaulting to it).
func HasBundle() bool { return len(strings.TrimSpace(embeddedBundle)) > 1000 }
