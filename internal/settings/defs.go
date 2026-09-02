package settings

// The keys this panel actually stores, each with the default that used to live
// inside whichever reader wanted it.
//
// Adding a key here is what makes it writable: Values refuses a key it does not
// know, so a typo in a handler fails the save loudly instead of writing a row
// nothing will ever read back.

import (
	"fmt"
	"strconv"
	"net"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/routing"
)

var defaults = buildRegistry()

// Defs is the registry every reader and writer in the panel shares.
func Defs() *Registry { return defaults }

// All returns every registered def, in registration order.
func All() []Def { return defaults.All() }

// Lookup resolves a stored key to its def.
func Lookup(key string) (Def, bool) { return defaults.Lookup(key) }

// Choices returns the legal values of an enum key, so the API serves the UI's
// dropdown from the same table the validator rejects against. The two lists
// were separate before, and only one of them was ever enforced.
func Choices(key string) []string {
	d, ok := defaults.Lookup(key)
	if !ok {
		return nil
	}
	return append([]string(nil), d.Choices...)
}

func buildRegistry() *Registry {
	r := NewRegistry()

	// --- host tuning ---------------------------------------------------------
	r.Register(Def{
		Key: "net_tune_bbr", Kind: KindBool, Scope: ScopePanel, Default: "0",
		Help: "Ask the host to use BBR congestion control with the fq queueing discipline, " +
			"re-applied on every panel start so a reboot or a kernel upgrade does not quietly revert it.",
	})

	// --- subscription rendering ---------------------------------------------
	r.Register(Def{
		Key: "sub_routing_preset", Kind: KindEnum, Scope: ScopeSubscription,
		Default: "iran", Choices: []string{"iran", "full", "block", "off"},
		Help: "Routing rules baked into every generated config. A per-request ?routing= overrides it.",
	})
	r.Register(Def{
		Key: "sub_fragment_default", Kind: KindBool, Scope: ScopeSubscription, Default: "0",
		Help: "Fragment the TLS hello in generated configs by default, on the cores listed below. A per-request ?fragment= overrides it.",
	})
	r.Register(Def{
		Key: "sub_fragment_level", Kind: KindEnum, Scope: ScopeSubscription,
		Default: "medium", Choices: []string{"light", "medium", "aggressive"},
		Help: "How hard generated configs fragment the TLS hello. medium is the shipped behaviour; " +
			"a per-request ?fragment_level= overrides it.",
	})
	r.Register(Def{
		Key: "sub_fragment_cores", Kind: KindStringList, Scope: ScopeSubscription,
		Default: "xray, sing-box",
		Help: "Which cores honour the TLS-fragment toggle. Clash-Meta has no fragment primitive " +
			"and cannot be listed.",
		Validate: everyEntryIsAFragmentCore,
	})
	r.Register(Def{
		Key: "sub_name_template", Kind: KindString, Scope: ScopeSubscription, Default: "",
		Help: "Node-naming template, e.g. \"{FLAG} {NAME}\". Empty leaves each node's own remark untouched.",
	})
	r.Register(Def{
		Key: "sub_pattern_default", Kind: KindEnum, Scope: ScopeSubscription,
		Default: "off", Choices: []string{"off", "only", "both"},
		Help: "Whether link and v2ray subscriptions carry the unsafe-uTLS \"pattern\" variant. A per-request ?patt= overrides it.",
	})
	r.Register(Def{
		Key: "sub_front_domain", Kind: KindDomain, Scope: ScopeSubscription, Default: "",
		Help: "Camouflage domain applied to every node in the subscription. Empty means no fronting.",
	})
	r.Register(Def{
		Key: "sub_front_mode", Kind: KindEnum, Scope: ScopeSubscription,
		Default: "none", Choices: []string{"none", "sni", "cdn"},
		Help: "How the camouflage domain is applied: sni rewrites Host+SNI, cdn fronts the transport Host only.",
	})
	r.Register(Def{
		// ON by default, and stored as "1"/"0" because the reader treats anything
		// other than "0" as on. A value of "false" here would read back as ON.
		Key: "sub_expand_sni", Kind: KindBool, Scope: ScopeSubscription, Default: "1",
		Help: "Fan a REALITY inbound out into one config per borrowed SNI. On by default — it is the point of listing several.",
	})
	r.Register(Def{
		Key: "sub_front_cleanip", Kind: KindBool, Scope: ScopeSubscription, Default: "0",
		Help: "Fan a CDN-frontable inbound out across the clean-IP list. Only useful once that list is set.",
	})
	r.Register(Def{
		Key: "sub_clean_ips", Kind: KindStringList, Scope: ScopeSubscription, Default: "",
		Help:     "Clean CDN edge addresses used for IP fan-out. Comma, space or newline separated.",
		Validate: everyEntryIsAnAddress,
	})

	// --- the panel's own public address --------------------------------------
	r.Register(Def{
		// A MIRROR of panel.json's domain, kept so a reader that only wants the
		// public hostname does not have to parse the config file. It is written
		// from the normalized value the panel settings service accepted, never
		// from raw operator input — the raw form leaked into generated links.
		Key: "public_address", Kind: KindDomain, Scope: ScopePanel, Default: "",
		Help: "Hostname exported links use when an inbound binds a wildcard address. Mirrors the panel domain.",
	})

	// --- panel self-update ----------------------------------------------------
	r.Register(Def{
		// "stable" reads /releases/latest, which by definition never returns a
		// prerelease — so an operator already running a release candidate could
		// not see the next one at all before this key existed.
		Key: "update_channel", Kind: KindEnum, Scope: ScopePanel, Default: "stable",
		Choices: []string{"stable", "prerelease"},
		Help:    "Which releases the panel offers as updates. \"prerelease\" includes release candidates.",
	})

	// --- Telegram alerts ------------------------------------------------------
	r.Register(Def{
		Key: "telegram_bot_token", Kind: KindSecret, Scope: ScopeTelegram, Default: "", Secret: true,
		Help: "Bot token from @BotFather. Set here it wins over FORGEPANEL_TELEGRAM_TOKEN.",
	})
	r.Register(Def{
		Key: "telegram_admin_ids", Kind: KindIntList, Scope: ScopeTelegram, Default: "",
		Help: "Chat ids that receive alerts. Negative for a group; message @userinfobot to find yours.",
	})
	r.Register(Def{
		Key: "telegram_backup_delivery", Kind: KindBool, Scope: ScopeTelegram, Default: "0",
		Help: "Ship each scheduled backup to those chats. Off by default: it sends the panel's whole state to a third party.",
	})

	// --- off-box backups to an S3-compatible bucket ---------------------------
	//
	// Appended after the Telegram block rather than woven into it: the listing
	// order is the registration order and is served to the UI, so inserting a
	// key in the middle reshuffles a list operators and tests both read.
	r.Register(Def{
		Key: "backup_s3_enabled", Kind: KindBool, Scope: ScopeBackup, Default: "0",
		Help: "Upload each scheduled backup to the bucket below. Off by default: it ships the panel's whole state off this machine.",
	})
	r.Register(Def{
		Key: "backup_s3_endpoint", Kind: KindString, Scope: ScopeBackup, Default: "",
		Help: "Base URL of the S3-compatible service, including the scheme, e.g. https://s3.example.com.",
	})
	r.Register(Def{
		Key: "backup_s3_region", Kind: KindString, Scope: ScopeBackup, Default: "us-east-1",
		Help: "Region to sign with. SigV4 requires one even where the service ignores it; leave this alone if unsure.",
	})
	r.Register(Def{
		Key: "backup_s3_bucket", Kind: KindString, Scope: ScopeBackup, Default: "",
		Help: "Bucket the backups are written to. It must already exist; the panel never creates one.",
	})
	r.Register(Def{
		Key: "backup_s3_prefix", Kind: KindString, Scope: ScopeBackup, Default: "",
		Help: "Optional key prefix, e.g. panel/, so one bucket can hold more than this panel's backups.",
	})
	r.Register(Def{
		Key: "backup_s3_access_key", Kind: KindString, Scope: ScopeBackup, Default: "",
		Help: "Access key id for the bucket.",
	})
	r.Register(Def{
		Key: "backup_s3_secret_key", Kind: KindSecret, Scope: ScopeBackup, Default: "", Secret: true,
		Help: "Secret access key. Write-only: the panel never shows it back.",
	})
	r.Register(Def{
		Key: "backup_s3_path_style", Kind: KindBool, Scope: ScopeBackup, Default: "1",
		Help: "Address the bucket as <endpoint>/<bucket>. On for minio and most self-hosted gateways; off for AWS-style <bucket>.<endpoint>.",
	})

	// --- panel-owned, never an operator surface -------------------------------
	r.Register(Def{
		Key: "edge_feed_pull_token", Kind: KindSecret, Scope: ScopeInternal, Default: "", Secret: true,
		Help: "Bearer the edge Worker presents to /api/edge/feed. Minted and rotated by the panel.",
	})
	r.Register(Def{
		Key: "pending_totp_", Kind: KindSecret, Scope: ScopeInternal, Default: "", Secret: true, Prefix: true,
		Help: "Per-admin TOTP secret held between 2FA setup and confirmation, then cleared.",
	})
	// The registered WARP device, as JSON: its WireGuard private key, the bearer
	// that can rebind it, and the endpoint in use.
	//
	// ScopeInternal and Secret: a ScopePanel key would be listed by
	// GET /api/admin/settings/registry, and this one holds a private key. It is
	// written only by the WARP provisioner, which owns its shape.
	r.Register(Def{
		Key: "warp_account", Kind: KindSecret, Scope: ScopeInternal, Default: "", Secret: true,
		Help: "The Cloudflare WARP device the panel registered, including its keys. Managed by /api/admin/routing/warp.",
	})
	r.Register(Def{
		Key: "warp_rotate_hours", Kind: KindString, Scope: ScopeInternal, Default: "0",
		Help: "How often, in whole hours, to move the WARP outbound to a different Cloudflare address. 0 is off.",
		// Validated here rather than at the handler so the table cannot hold a
		// value the rotator will silently read as "off".
		Validate: func(v string) error {
			v = strings.TrimSpace(v)
			if v == "" {
				return nil
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("must be a whole number of hours, got %q", v)
			}
			if n < 0 {
				return fmt.Errorf("cannot be negative, got %d", n)
			}
			return nil
		},
	})
	// Operator-selected core versions, and the version each one displaced so a
	// rollback has a target. Empty means "the version this build shipped with".
	//
	// ScopeInternal on purpose: a ScopePanel key would be listed by
	// GET /api/admin/settings/registry as a plain string field, advertising a way
	// to set a core version WITHOUT a digest — which is precisely the path
	// /api/admin/cores/:engine/pin exists to keep closed.
	for _, e := range []string{"xray", "sing-box", "brook"} {
		r.Register(Def{
			Key: "core_version_" + e, Kind: KindString, Scope: ScopeInternal, Default: "",
			Help: "Operator-selected " + e + " version. Empty uses the version this build shipped with.",
		})
		r.Register(Def{
			Key: "core_version_prev_" + e, Kind: KindString, Scope: ScopeInternal, Default: "",
			Help: "The " + e + " version the current selection displaced, and the target of a rollback.",
		})
	}

	return r
}

// everyEntryIsAnAddress rejects a clean-IP list with a typo in it. An unusable
// entry here is invisible: the fan-out still renders a config, it just points at
// nothing, and the operator sees "some of my configs do not connect".
func everyEntryIsAnAddress(v string) error {
	for _, f := range SplitList(v) {
		if net.ParseIP(f) != nil || ValidDomain(strings.ToLower(f)) {
			continue
		}
		return fmt.Errorf("%q is neither an IP address nor a hostname", f)
	}
	return nil
}

// everyEntryIsAFragmentCore rejects a core the fragment toggle cannot reach.
// "clash" is the one an operator actually tries: mihomo has no fragment
// primitive, so accepting it would store a preference that silently does
// nothing and leave them believing their Clash subscribers are protected.
func everyEntryIsAFragmentCore(v string) error {
	legal := routing.FragmentCores()
	for _, f := range SplitList(v) {
		if !contains(legal, strings.ToLower(f)) {
			return fmt.Errorf("%q cannot fragment the TLS hello; only %s can", f, strings.Join(legal, ", "))
		}
	}
	return nil
}
