package edgebot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/edge"
)

// Router turns one inbound Telegram event into outbound messages. It is
// transport-agnostic and holds no network state of its own: everything it needs
// is the Store (persistence) and Ops (Cloudflare / Worker actions), both
// injectable, so the whole command surface is unit-testable against fakes.

// Incoming is one normalised update — a message or a tapped inline button.
type Incoming struct {
	UserID       int64
	ChatID       int64
	Username     string
	Name         string
	Text         string
	MessageID    int64
	IsCallback   bool
	CallbackID   string
	CallbackData string
}

// Button is one inline keyboard button.
type Button struct{ Text, Data string }

// Out is one message to send.
type Out struct {
	ChatID  int64
	Text    string
	Buttons [][]Button
}

// Result is everything the transport should do for one Incoming.
type Result struct {
	Outs           []Out
	DeleteIncoming bool   // scrub the user's message (a /cf credential)
	CallbackAnswer string // toast on a tapped button
}

// Router dispatches commands.
type Router struct {
	store       *Store
	ops         Ops
	botUsername string
}

// NewRouter builds a router over a store and ops implementation.
func NewRouter(store *Store, ops Ops) *Router {
	return &Router{store: store, ops: ops}
}

// SetBotUsername records the bot's @name for help text and group-command parsing.
func (r *Router) SetBotUsername(name string) { r.botUsername = name }

// reply is a single-message result to the incoming chat.
func (r *Router) reply(in Incoming, text string) Result {
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: text}}}
}

// Handle is the entry point.
func (r *Router) Handle(ctx context.Context, in Incoming) Result {
	if in.IsCallback {
		return r.handleCallback(ctx, in)
	}
	text := strings.TrimSpace(in.Text)
	if text == "" {
		return Result{}
	}

	owner := r.store.IsOwner(in.UserID)
	approved := owner || r.store.IsApproved(in.UserID)

	// Gate: anyone not yet approved is funnelled into the request flow, whatever
	// they typed. /start is just the most common way they arrive.
	if !approved {
		return r.handleAccessRequest(in)
	}

	cmd, args := parseCommand(text, r.botUsername)
	switch cmd {
	case "start", "menu":
		return r.handleStart(in)
	case "help":
		return Result{Outs: []Out{{ChatID: in.ChatID, Text: r.helpText(owner), Buttons: homeButton()}}}
	case "cf":
		return r.handleCF(ctx, in, args)
	case "whoami":
		return r.handleWhoami(in)
	case "deploy":
		return r.handleDeploy(ctx, in, args)
	case "list", "ls":
		return r.handleList(in)
	case "status":
		return r.handleStatus(ctx, in, args)
	case "config":
		return r.handleConfigDump(ctx, in, args)
	case "sub", "links":
		return r.handleSub(ctx, in, args)
	case "rotate":
		return r.handleRotate(ctx, in, args)
	case "update":
		return r.handleUpdate(ctx, in, args)
	case "destroy", "delete":
		return r.handleDestroyAsk(in, args)
	case "domain":
		return r.handleDomain(ctx, in, args)
	case "warp":
		return r.handleWarp(ctx, in, args)
	case "warpconf":
		return r.handleWarpConf(ctx, in, args)
	// --- config editor (router_config.go) ---
	case "addip", "rmip", "ips", "probeip", "refreships", "refreshext",
		"sni", "cdnhost", "cdnaddr", "ports", "fingerprint", "fragment",
		"proxyip", "nat64", "chain", "backend", "extsub", "protocols":
		return r.handleConfigCommand(ctx, in, cmd, args)
	// --- owner-only ---
	case "users":
		return r.handleUsers(in)
	case "approve", "deny", "revoke":
		return r.handleDecision(ctx, in, cmd, args)
	default:
		return Result{Outs: []Out{{ChatID: in.ChatID, Text: "🤔 I didn't catch that. Here's the menu:", Buttons: r.homeButtons(in.UserID)}}}
	}
}

// parseCommand splits "/cmd@bot arg1 arg2" into ("cmd", ["arg1","arg2"]).
func parseCommand(text, botUsername string) (string, []string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return "", nil
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	if i := strings.IndexByte(cmd, '@'); i >= 0 { // strip @botname in groups
		cmd = cmd[:i]
	}
	return strings.ToLower(cmd), fields[1:]
}

// --- access / onboarding ----------------------------------------------------

func (r *Router) handleAccessRequest(in Incoming) Result {
	outcome, _ := r.store.EnsureRequest(in.UserID, in.Username, in.Name)
	switch outcome {
	case RequestNew:
		who := describeUser(in.UserID, in.Username, in.Name)
		ownerMsg := Out{
			ChatID: r.store.Owner(),
			Text:   "🔔 New access request for ForgeEdge Bot:\n" + who + "\n\nApprove to let them deploy their own Workers.",
			Buttons: [][]Button{{
				{Text: "✅ Approve", Data: "approve:" + strconv.FormatInt(in.UserID, 10)},
				{Text: "❌ Deny", Data: "deny:" + strconv.FormatInt(in.UserID, 10)},
			}},
		}
		userMsg := Out{ChatID: in.ChatID, Text: "👋 Request sent. The owner has to approve you before you can use the bot — you'll get a message here when they do."}
		return Result{Outs: []Out{userMsg, ownerMsg}}
	case RequestPending:
		return r.reply(in, "⏳ Your request is still waiting for the owner to approve. Hang tight.")
	case RequestBlocked:
		return r.reply(in, "🚫 You don't have access to this bot.")
	default: // RequestApproved (owner) shouldn't reach here
		return r.reply(in, r.helpText(r.store.IsOwner(in.UserID)))
	}
}

func (r *Router) handleUsers(in Incoming) Result {
	if !r.store.IsOwner(in.UserID) {
		return r.reply(in, "That command is owner-only.")
	}
	users := r.store.ListUsers()
	if len(users) == 0 {
		return r.reply(in, "No users have contacted the bot yet.")
	}
	var b strings.Builder
	b.WriteString("Users:\n")
	for _, u := range users {
		icon := map[Status]string{StatusApproved: "✅", StatusPending: "⏳", StatusRevoked: "🚫", StatusDenied: "🚫"}[u.Status]
		fmt.Fprintf(&b, "%s %s — %s", icon, describeUser(u.ID, u.Username, u.Name), u.Status)
		if n := len(u.Deployments); n > 0 {
			fmt.Fprintf(&b, " · %d worker(s)", n)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nManage: /approve <id> · /deny <id> · /revoke <id>")
	return r.reply(in, b.String())
}

// handleDecision serves the typed /approve|/deny|/revoke <id> forms.
func (r *Router) handleDecision(ctx context.Context, in Incoming, cmd string, args []string) Result {
	if !r.store.IsOwner(in.UserID) {
		return r.reply(in, "That command is owner-only.")
	}
	if len(args) < 1 {
		return r.reply(in, "Usage: /"+cmd+" <telegram_id>")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return r.reply(in, "That doesn't look like a Telegram id. Get it from /users.")
	}
	return r.decide(in, cmd, id)
}

// decide is the shared body for typed commands and tapped buttons.
func (r *Router) decide(in Incoming, action string, targetID int64) Result {
	var status Status
	var note string
	switch action {
	case "approve":
		status, note = StatusApproved, "✅ Approved. They can use the bot now."
	case "deny":
		status, note = StatusDenied, "❌ Denied."
	case "revoke":
		status, note = StatusRevoked, "🚫 Revoked — they can no longer use the bot."
	default:
		return r.reply(in, "Unknown decision.")
	}
	if err := r.store.Decide(targetID, status); err != nil {
		return r.reply(in, "Could not record that: "+err.Error())
	}
	outs := []Out{{ChatID: in.ChatID, Text: note}}
	// Tell the affected user, except on revoke where a silent cut-off is kinder.
	if status == StatusApproved {
		outs = append(outs, Out{ChatID: targetID,
			Text:    "🎉 You're in! Welcome to ForgeEdge.\n\nI'll create your own Cloudflare Worker VPN edge and let you manage it right here. First, connect your Cloudflare account:",
			Buttons: [][]Button{{{Text: "🔑 Connect Cloudflare", Data: "m:cf"}, {Text: "❓ Help", Data: "m:help"}}}})
	}
	res := Result{Outs: outs}
	if in.IsCallback {
		res.CallbackAnswer = note
	}
	return res
}

func (r *Router) handleCallback(ctx context.Context, in Incoming) Result {
	data := in.CallbackData
	parts := strings.SplitN(data, ":", 3)
	switch parts[0] {
	case "approve", "deny", "revoke":
		if !r.store.IsOwner(in.UserID) {
			return Result{CallbackAnswer: "Owner only."}
		}
		if len(parts) < 2 {
			return Result{CallbackAnswer: "Malformed."}
		}
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return Result{CallbackAnswer: "Bad id."}
		}
		return r.decide(in, parts[0], id)
	case "destroy":
		// destroy:<name> — confirmed deletion from the inline button.
		if len(parts) < 2 {
			return Result{CallbackAnswer: "Malformed."}
		}
		if !r.store.IsApproved(in.UserID) {
			return Result{CallbackAnswer: "Not authorized."}
		}
		return r.doDestroy(ctx, in, parts[1])
	case "cancel":
		return Result{CallbackAnswer: "Cancelled.", Outs: []Out{{ChatID: in.ChatID, Text: "Cancelled — nothing was deleted."}}}
	case "home", "m", "w":
		// Navigation buttons — approved users (and the owner) only.
		if !r.store.IsApproved(in.UserID) {
			return Result{CallbackAnswer: "Not authorized."}
		}
		return r.handleMenuCallback(ctx, in, data)
	default:
		return Result{}
	}
}

// --- credentials ------------------------------------------------------------

func (r *Router) handleCF(ctx context.Context, in Incoming, args []string) Result {
	// Always scrub the message: it carries a live API token.
	res := Result{DeleteIncoming: true}
	if len(args) < 1 {
		res.Outs = []Out{{ChatID: in.ChatID, Text: cfHowTo(), Buttons: homeButton()}}
		return res
	}
	token := args[0]
	account := ""
	if len(args) >= 2 {
		account = args[1]
	}
	resolved, err := r.ops.VerifyCreds(ctx, token, account)
	if err != nil {
		res.Outs = []Out{{ChatID: in.ChatID, Text: "❌ That token didn't verify:\n" + errText(err) + "\n\nTap 🔑 to see how to make a good one.",
			Buttons: [][]Button{{{Text: "🔑 How to get a token", Data: "m:cf"}, {Text: "🏠 Menu", Data: "home"}}}}}
		return res
	}
	if err := r.store.SetCreds(in.UserID, token, resolved); err != nil {
		res.Outs = []Out{{ChatID: in.ChatID, Text: "Stored the token but couldn't save: " + err.Error()}}
		return res
	}
	res.Outs = []Out{{ChatID: in.ChatID, Text: "✅ Cloudflare connected! (token stored encrypted, your message deleted)\nAccount: " + resolved + "\n\n🚀 Ready — tap Deploy to create your first edge.",
		Buttons: [][]Button{{{Text: "🚀 Deploy edge", Data: "m:deploy"}, {Text: "🏠 Menu", Data: "home"}}}}}
	return res
}

func (r *Router) handleWhoami(in Incoming) Result {
	u, ok := r.store.Lookup(in.UserID)
	role := "user"
	if r.store.IsOwner(in.UserID) {
		role = "owner"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "You are %s (%s).\n", describeUser(in.UserID, in.Username, in.Name), role)
	if ok && u.HasCreds() {
		fmt.Fprintf(&b, "Cloudflare account: %s\n", u.CFAccount)
	} else {
		b.WriteString("No Cloudflare credentials stored yet — set them with /cf.\n")
	}
	fmt.Fprintf(&b, "Workers: %d", len(r.store.Deployments(in.UserID)))
	return r.reply(in, b.String())
}

// --- shared helpers ---------------------------------------------------------

// requireCreds fetches the caller's stored Cloudflare creds or an error message.
func (r *Router) requireCreds(userID int64) (token, account string, errMsg string) {
	t, a, ok := r.store.Creds(userID)
	if !ok {
		return "", "", "Set your Cloudflare credentials first: /cf <api_token> [account_id]"
	}
	return t, a, ""
}

// mustDeployment resolves which Worker a command targets. If the first arg names
// one it's used; otherwise, if the user has exactly one Worker, that's assumed.
func (r *Router) mustDeployment(userID int64, args []string) (Deployment, []string, string) {
	deps := r.store.Deployments(userID)
	if len(deps) == 0 {
		return Deployment{}, nil, "You have no Workers yet. Deploy one with /deploy."
	}
	if len(args) > 0 {
		for _, d := range deps {
			if d.Name == args[0] {
				return d, args[1:], ""
			}
		}
	}
	if len(deps) == 1 {
		return deps[0], args, ""
	}
	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	sort.Strings(names)
	return Deployment{}, nil, "You have several Workers — name which one: " + strings.Join(names, ", ")
}

func (r *Router) helpText(owner bool) string {
	var b strings.Builder
	b.WriteString("ForgeEdge Bot — deploy & manage your Cloudflare Worker edges from chat.\n\n")
	b.WriteString("Setup\n")
	b.WriteString("  /cf <token> [account]   store your Cloudflare creds (message auto-deleted)\n")
	b.WriteString("  /whoami                 show your account + worker count\n\n")
	b.WriteString("Workers\n")
	b.WriteString("  /deploy [name] [domain] deploy a new edge\n")
	b.WriteString("  /list                   your workers\n")
	b.WriteString("  /status [name]          live worker status\n")
	b.WriteString("  /sub [name]             subscription + free-config links\n")
	b.WriteString("  /config [name]          dump the worker config\n")
	b.WriteString("  /update [name]          re-upload the latest worker build\n")
	b.WriteString("  /rotate [name]          rotate the secret path (kills old URLs)\n")
	b.WriteString("  /destroy [name]         delete a worker\n\n")
	b.WriteString("Clean IPs / CDN fronting\n")
	b.WriteString("  /addip [name] <ip…>   /rmip [name] <ip>   /ips [name]\n")
	b.WriteString("  /probeip [name] <ip>  /refreships [name]\n")
	b.WriteString("  /sni [name] <sni>     /cdnhost [name] <host>   /cdnaddr [name] <addr…>\n\n")
	b.WriteString("Transport / obfuscation\n")
	b.WriteString("  /ports [name] <p…>    /fingerprint [name] <fp>   /fragment [name] on|off [len] [delay]\n")
	b.WriteString("  /proxyip [name] <ip…> /nat64 [name] <prefix…>    /chain [name] <uri|off>\n")
	b.WriteString("  /protocols [name] vless,trojan\n\n")
	b.WriteString("Backends / subs / domain\n")
	b.WriteString("  /backend [name] <url|off> [token]   /extsub [name] add|rm|list <url>   /domain [name] <host>\n\n")
	b.WriteString("WARP (WireGuard + AmneziaWG)\n")
	b.WriteString("  /warp [name]          register + attach a WARP pair\n")
	b.WriteString("  /warpconf [name]      download the wg-quick .conf\n")
	if owner {
		b.WriteString("\nOwner\n")
		b.WriteString("  /users                list requests + approved\n")
		b.WriteString("  /approve <id>  /deny <id>  /revoke <id>\n")
	}
	return b.String()
}

// describeUser renders "Name (@user, 123)" with whatever is known.
func describeUser(id int64, username, name string) string {
	parts := []string{}
	if name != "" {
		parts = append(parts, name)
	}
	tag := ""
	if username != "" {
		tag = "@" + username + ", "
	}
	return fmt.Sprintf("%s(%s%d)", join(parts), tag, id)
}

func join(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + " "
}

// errText renders an error for chat, appending an edge remediation when present.
func errText(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := edge.AsError(err); ok {
		msg := e.Message
		if e.Remediation != "" {
			msg += "\n→ " + e.Remediation
		}
		return msg
	}
	return err.Error()
}
