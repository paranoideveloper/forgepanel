package edgebot

import (
	"context"
	"strings"
)

// router_menu.go makes the bot feel like an app instead of a command line:
// a home screen with buttons, a per-worker menu, and Telegram's "/" command
// list. Every button maps to the same handlers the typed commands use, so power
// users keep the commands and everyone else can just tap.

// menuCommands is the "/" autocomplete + blue Menu button list. Kept short and
// task-ordered — the full surface is in /help.
func menuCommands() []BotCommand {
	return []BotCommand{
		{Command: "start", Description: "🏠 Home menu"},
		{Command: "deploy", Description: "🚀 Deploy a new edge"},
		{Command: "list", Description: "📋 My edges"},
		{Command: "status", Description: "📊 Check an edge"},
		{Command: "sub", Description: "🔗 Get share / import links"},
		{Command: "addip", Description: "➕ Add a clean Cloudflare IP"},
		{Command: "cf", Description: "🔑 Connect your Cloudflare account"},
		{Command: "help", Description: "❓ All commands"},
	}
}

// homeButtons is the main menu.
func (r *Router) homeButtons(userID int64) [][]Button {
	rows := [][]Button{
		{{Text: "🚀 Deploy edge", Data: "m:deploy"}, {Text: "📋 My edges", Data: "m:list"}},
		{{Text: "🔑 Connect Cloudflare", Data: "m:cf"}, {Text: "❓ Help", Data: "m:help"}},
	}
	if r.store.IsOwner(userID) {
		rows = append(rows, []Button{{Text: "👥 Manage users", Data: "m:users"}})
	}
	return rows
}

// homeText greets the user and shows where they stand (creds set? edges?).
func (r *Router) homeText(in Incoming) string {
	name := firstWord(in.Name)
	if name == "" {
		name = "there"
	}
	var b strings.Builder
	b.WriteString("👋 Hey " + name + "! I'm ForgeEdge — I spin up your own Cloudflare Worker VPN edge and let you manage it right here.\n\n")

	_, hasCreds := func() (string, bool) { t, _, ok := r.store.Creds(in.UserID); return t, ok }()
	edges := len(r.store.Deployments(in.UserID))

	switch {
	case !hasCreds:
		b.WriteString("👉 First step: tap 🔑 Connect Cloudflare (takes ~1 min).")
	case edges == 0:
		b.WriteString("✅ Cloudflare connected. Next: tap 🚀 Deploy edge to create your first one.")
	default:
		b.WriteString("✅ You have " + plural(edges, "edge", "edges") + ". Tap 📋 My edges to manage them, or 🚀 Deploy edge for another.")
	}
	return b.String()
}

// handleStart / handleMenu render the home screen.
func (r *Router) handleStart(in Incoming) Result {
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: r.homeText(in), Buttons: r.homeButtons(in.UserID)}}}
}

// homeButton is a single "back to menu" row appended to deeper screens.
func homeButton() [][]Button { return [][]Button{{{Text: "🏠 Menu", Data: "home"}}} }

// workerButtons is the per-edge action menu.
func workerButtons(name string) [][]Button {
	return [][]Button{
		{{Text: "📊 Status", Data: "w:status:" + name}, {Text: "🔗 Links", Data: "w:sub:" + name}},
		{{Text: "➕ Add clean IP", Data: "w:addip:" + name}, {Text: "🗑 Delete", Data: "w:del:" + name}},
		{{Text: "🏠 Menu", Data: "home"}},
	}
}

// handleMenuCallback routes the home / edge navigation buttons. Everything here
// is behind the approved gate (checked in handleCallback before dispatch).
func (r *Router) handleMenuCallback(ctx context.Context, in Incoming, data string) Result {
	switch {
	case data == "home":
		return Result{CallbackAnswer: "", Outs: []Out{{ChatID: in.ChatID, Text: r.homeText(in), Buttons: r.homeButtons(in.UserID)}}}

	case data == "m:help":
		return Result{Outs: []Out{{ChatID: in.ChatID, Text: r.helpText(r.store.IsOwner(in.UserID)), Buttons: homeButton()}}}

	case data == "m:cf":
		return Result{Outs: []Out{{ChatID: in.ChatID, Text: cfHowTo(), Buttons: homeButton()}}}

	case data == "m:users":
		if !r.store.IsOwner(in.UserID) {
			return Result{CallbackAnswer: "Owner only."}
		}
		return r.handleUsers(in)

	case data == "m:list":
		return r.handleList(in)

	case data == "m:deploy":
		if _, _, ok := r.store.Creds(in.UserID); !ok {
			return Result{CallbackAnswer: "Connect Cloudflare first",
				Outs: []Out{{ChatID: in.ChatID, Text: "🔑 First connect your Cloudflare account, then I can deploy.\n\n" + cfHowTo(), Buttons: homeButton()}}}
		}
		return Result{CallbackAnswer: "Deploying…",
			Outs: append([]Out{{ChatID: in.ChatID, Text: "🚀 Deploying a new edge — this takes ~30s…"}}, r.handleDeploy(ctx, in, nil).Outs...)}

	case strings.HasPrefix(data, "w:menu:"):
		name := strings.TrimPrefix(data, "w:menu:")
		if _, ok := r.store.Deployment(in.UserID, name); !ok {
			return Result{CallbackAnswer: "Gone."}
		}
		return Result{Outs: []Out{{ChatID: in.ChatID, Text: "⚙️ " + name + " — pick an action:", Buttons: workerButtons(name)}}}

	case strings.HasPrefix(data, "w:status:"):
		return r.handleStatus(ctx, in, []string{strings.TrimPrefix(data, "w:status:")})

	case strings.HasPrefix(data, "w:sub:"):
		return r.handleSub(ctx, in, []string{strings.TrimPrefix(data, "w:sub:")})

	case strings.HasPrefix(data, "w:addip:"):
		name := strings.TrimPrefix(data, "w:addip:")
		return Result{Outs: []Out{{ChatID: in.ChatID,
			Text:    "➕ To add a clean Cloudflare IP to " + name + ", send:\n\n/addip " + name + " 188.114.96.3\n\n(you can list several, space-separated). Tip: /refreships " + name + " auto-mints fresh ones.",
			Buttons: [][]Button{{{Text: "⚙️ " + name, Data: "w:menu:" + name}, {Text: "🏠 Menu", Data: "home"}}}}}}

	case strings.HasPrefix(data, "w:del:"):
		return r.handleDestroyAsk(in, []string{strings.TrimPrefix(data, "w:del:")})
	}
	return Result{}
}

// cfHowTo is the shared, friendly "how to get a token" explainer.
func cfHowTo() string {
	return "🔑 Connect your Cloudflare account (1 minute):\n\n" +
		"1️⃣ Open dash.cloudflare.com → My Profile → API Tokens → Create Token → Create Custom Token.\n" +
		"2️⃣ Give it these permissions:\n" +
		"   • Account · Workers Scripts · Edit\n" +
		"   • Account · Workers KV Storage · Edit\n" +
		"   • Account · Account Settings · Read\n" +
		"   (+ Zone · Read and Zone · DNS · Edit if you'll add a custom domain)\n" +
		"3️⃣ Copy the token and send it to me:\n\n" +
		"/cf YOUR_TOKEN\n\n" +
		"🔒 I verify it, store it encrypted, and delete your message instantly."
}

// --- tiny text helpers ------------------------------------------------------

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
