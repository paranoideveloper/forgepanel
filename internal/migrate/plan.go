package migrate

// Deciding what an import WOULD do, before it does any of it.
//
// The importer read a foreign panel's database and printed JSON. Nothing was
// written, so "migrate from 3x-ui" meant reading the output and re-typing it.
//
// The plan exists as a separate step because an import is the one operation an
// operator runs exactly once, against a panel they have not used before, with
// data they cannot easily reconstruct. Being able to see "this would create 14
// inbounds and skip 2 because their ports are taken" BEFORE anything is written
// is the difference between a migration and a gamble.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Action is what the import would do with one item.
type Action string

const (
	// ActionCreate is the ordinary case.
	ActionCreate Action = "create"
	// ActionSkip means the item is already present and importing it again would
	// duplicate it. Running an import twice must not double the fleet.
	ActionSkip Action = "skip"
	// ActionConflict means the item CANNOT be imported as-is and the operator has
	// to decide. It is separate from skip because a skip is safe to ignore and a
	// conflict is data that will not arrive.
	ActionConflict Action = "conflict"
)

// PlannedInbound is one inbound the import considered.
type PlannedInbound struct {
	Remark   string        `json:"remark"`
	Protocol string        `json:"protocol"`
	Port     int           `json:"port"`
	Action   Action        `json:"action"`
	Reason   string        `json:"reason,omitempty"`
	Users    []PlannedUser `json:"users"`
	Node     *model.Node   `json:"-"`
	// SourceKey is the provenance stamped onto the row if it is created, so a
	// later re-import recognises it even after a rename on either side.
	SourceKey string `json:"source_key,omitempty"`
}

// PlannedUser is one client the import considered.
type PlannedUser struct {
	Username string `json:"username"`
	Action   Action `json:"action"`
	Reason   string `json:"reason,omitempty"`
	// Source carries the credentials lifted from the foreign panel. Never
	// serialised: a dry-run response that echoed every user's UUID would put the
	// whole imported credential set in a log or a browser history.
	Source ImportedUser `json:"-"`
}

// Plan is a complete dry run.
type Plan struct {
	Inbounds []PlannedInbound `json:"inbounds"`
	Warnings []string         `json:"warnings"`
	// Counts are what an operator actually reads before deciding.
	CreateInbounds   int `json:"create_inbounds"`
	SkipInbounds     int `json:"skip_inbounds"`
	ConflictInbounds int `json:"conflict_inbounds"`
	CreateUsers      int `json:"create_users"`
	SkipUsers        int `json:"skip_users"`
}

// Existing describes what the panel already holds, so the plan can tell a fresh
// import from a repeat.
type Existing struct {
	// PortsInUse maps a port to the remark of whatever holds it, so a conflict
	// can name the obstacle rather than just the number.
	PortsInUse map[int]string
	// ImportedSources maps an import-source key to the remark of the row that
	// carries it. This is the RELIABLE identity check: it survives a rename on
	// either side, which matching on the remark does not.
	ImportedSources map[string]string
	// Remarks and Usernames are the fallback identity checks, for rows that
	// predate provenance tracking or were created by hand.
	Remarks   map[string]bool
	Usernames map[string]bool
}

// SourceKey identifies a row in a foreign panel.
//
// The panel name is part of it because two different source panels can both have
// an inbound with id 3, and treating those as the same row would make importing
// the second one a no-op.
func SourceKey(panel string, id uint) string {
	return fmt.Sprintf("%s:%d", panel, id)
}

// BuildPlan decides what would happen, without touching anything.
func BuildPlan(res *Result, ex Existing) *Plan { return BuildPlanFrom(res, ex, "foreign") }

// BuildPlanFrom is BuildPlan with the source panel named, so provenance keys can
// distinguish two panels that both number their inbounds from one.
func BuildPlanFrom(res *Result, ex Existing, sourcePanel string) *Plan {
	p := &Plan{Warnings: append([]string(nil), res.Warnings...)}
	if ex.PortsInUse == nil {
		ex.PortsInUse = map[int]string{}
	}
	if ex.ImportedSources == nil {
		ex.ImportedSources = map[string]string{}
	}
	if ex.Remarks == nil {
		ex.Remarks = map[string]bool{}
	}
	if ex.Usernames == nil {
		ex.Usernames = map[string]bool{}
	}

	// Ports claimed EARLIER IN THIS PLAN count too. A foreign panel can hold two
	// inbounds on one port (disabled, or on different addresses); importing both
	// would produce a config the core refuses to start.
	claimed := map[int]string{}
	seenUsers := map[string]bool{}

	for _, imp := range res.Inbounds {
		if imp.Node == nil {
			continue
		}
		key := ""
		if imp.SourceID != 0 {
			key = SourceKey(sourcePanel, imp.SourceID)
		}
		pi := PlannedInbound{
			Remark: imp.Node.Remark, Protocol: string(imp.Node.Protocol),
			Port: imp.Node.Port, Action: ActionCreate, Node: imp.Node,
			SourceKey: key,
		}
		switch {
		case key != "" && ex.ImportedSources[key] != "":
			// Already imported from this exact source row. Recognised even if
			// either side has been renamed since, which is the whole point.
			pi.Action = ActionSkip
			pi.Reason = fmt.Sprintf("already imported as %q", ex.ImportedSources[key])
		case ex.Remarks[imp.Node.Remark]:
			pi.Action = ActionSkip
			pi.Reason = "an inbound with this name already exists; importing again would duplicate it"
		case ex.PortsInUse[imp.Node.Port] != "":
			pi.Action = ActionConflict
			pi.Reason = fmt.Sprintf("port %d is already used by %q", imp.Node.Port, ex.PortsInUse[imp.Node.Port])
		case claimed[imp.Node.Port] != "":
			pi.Action = ActionConflict
			pi.Reason = fmt.Sprintf("port %d is claimed by %q earlier in this import", imp.Node.Port, claimed[imp.Node.Port])
		default:
			claimed[imp.Node.Port] = imp.Node.Remark
		}

		for _, u := range imp.Users {
			name := usernameFor(u)
			pu := PlannedUser{Username: name, Action: ActionCreate, Source: u}
			switch {
			case name == "":
				pu.Action = ActionConflict
				pu.Reason = "this client has no email or identifier to derive a username from"
			case ex.Usernames[name]:
				pu.Action = ActionSkip
				pu.Reason = "a user with this name already exists"
			case seenUsers[name]:
				// One client can appear on several inbounds in a foreign panel;
				// that is one person, not several accounts.
				pu.Action = ActionSkip
				pu.Reason = "already being imported from another inbound"
			default:
				seenUsers[name] = true
			}
			pi.Users = append(pi.Users, pu)
		}
		p.Inbounds = append(p.Inbounds, pi)
	}

	// Sorted so two runs against the same source produce the same plan, and a
	// diff between them means something.
	sort.SliceStable(p.Inbounds, func(i, j int) bool {
		if p.Inbounds[i].Port != p.Inbounds[j].Port {
			return p.Inbounds[i].Port < p.Inbounds[j].Port
		}
		return p.Inbounds[i].Remark < p.Inbounds[j].Remark
	})

	for _, pi := range p.Inbounds {
		switch pi.Action {
		case ActionCreate:
			p.CreateInbounds++
		case ActionSkip:
			p.SkipInbounds++
		case ActionConflict:
			p.ConflictInbounds++
		}
		for _, pu := range pi.Users {
			// Users of an inbound that will not be created are not counted as
			// arriving: reporting them would overstate what the import delivers.
			if pi.Action != ActionCreate {
				continue
			}
			if pu.Action == ActionCreate {
				p.CreateUsers++
			} else {
				p.SkipUsers++
			}
		}
	}
	return p
}

// usernameFor derives a panel username from a foreign client.
//
// Foreign panels identify a client by an "email" that is usually not an email at
// all — it is a label. It is used verbatim where usable, because an operator
// migrating recognises their own names and a generated one would make every
// account unidentifiable.
func usernameFor(u ImportedUser) string {
	name := strings.TrimSpace(u.Email)
	// Strip a domain if one is present: "alice@panel.local" is one person called
	// alice, and carrying the foreign panel's hostname into every username is
	// noise that never goes away.
	if i := strings.Index(name, "@"); i > 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}
