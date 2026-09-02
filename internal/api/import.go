package api

import (
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/parse"
)

// ImportAny is the Paste-Anything importer (spec §8.3): it accepts a single
// share link, a whitespace/newline-separated list of links, or a base64
// subscription blob, and returns the parsed canonical nodes plus per-line
// errors. Clash YAML / sing-box JSON / foreign panel DB import is handled by the
// full build's dedicated migrators (spec §13); this covers the link + sub-blob
// cases that dominate real usage.
func ImportAny(text string) ([]*model.Node, []string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, []string{"empty input"}
	}
	// If it decodes as base64 and the result looks like links, treat it as a
	// subscription blob.
	if !strings.Contains(text, "://") {
		if raw, err := model.DecodeBase64Any(strings.TrimSpace(text)); err == nil && strings.Contains(string(raw), "://") {
			text = string(raw)
		}
	}
	var (
		nodes []*model.Node
		errs  []string
	)
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		n, err := parse.URI(line)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 && len(errs) == 0 {
		errs = append(errs, "no recognizable links found")
	}
	return nodes, errs
}
