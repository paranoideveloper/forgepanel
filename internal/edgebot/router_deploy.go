package edgebot

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// router_deploy.go — the Worker lifecycle commands and the ones that read a
// deployed Worker back (status, subscription links, WARP).

func (r *Router) handleDeploy(ctx context.Context, in Incoming, args []string) Result {
	token, account, errMsg := r.requireCreds(in.UserID)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	name, domain := "", ""
	if len(args) >= 1 {
		name = args[0]
	}
	if len(args) >= 2 {
		domain = args[1]
	}
	d, err := r.ops.Deploy(ctx, token, account, name, domain)
	if err != nil {
		return r.reply(in, "❌ Deploy failed:\n"+errText(err))
	}
	if err := r.store.AddDeployment(in.UserID, d); err != nil {
		return r.reply(in, "Deployed, but couldn't save it locally: "+err.Error()+"\nWorker: "+d.Origin)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "✅ Your edge is live: %s\n\n", d.Name)
	fmt.Fprintf(&b, "🌐 URL          %s\n", d.Origin)
	fmt.Fprintf(&b, "🔗 Subscription %s\n", d.SubTemplate())
	fmt.Fprintf(&b, "📥 Free config  %s\n", d.SharedSub())
	if d.Domain != "" {
		fmt.Fprintf(&b, "🏷 Domain       https://%s\n", d.Domain)
	}
	b.WriteString("\n💡 To work well from Iran, add a clean Cloudflare IP next — tap ➕ below.")
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: b.String(), Buttons: [][]Button{
		{{Text: "➕ Add clean IP", Data: "w:addip:" + d.Name}, {Text: "🔗 Links", Data: "w:sub:" + d.Name}},
		{{Text: "📊 Status", Data: "w:status:" + d.Name}, {Text: "🏠 Menu", Data: "home"}},
	}}}}
}

func (r *Router) handleList(in Incoming) Result {
	deps := r.store.Deployments(in.UserID)
	if len(deps) == 0 {
		return r.reply(in, "No Workers yet. Deploy one with /deploy.")
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	var b strings.Builder
	b.WriteString("📋 Your edges — tap one to manage it:\n")
	var rows [][]Button
	for _, d := range deps {
		line := d.Origin
		if d.Domain != "" {
			line += " (+" + d.Domain + ")"
		}
		fmt.Fprintf(&b, "\n• %s\n  %s\n", d.Name, line)
		rows = append(rows, []Button{{Text: "⚙️ " + d.Name, Data: "w:menu:" + d.Name}})
	}
	rows = append(rows, []Button{{Text: "🚀 Deploy another", Data: "m:deploy"}, {Text: "🏠 Menu", Data: "home"}})
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: b.String(), Buttons: rows}}}
}

func (r *Router) handleStatus(ctx context.Context, in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	st, err := r.ops.Status(ctx, d)
	if err != nil {
		return r.reply(in, "Couldn't reach "+d.Name+":\n"+errText(err))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", d.Name)
	fmt.Fprintf(&b, "  version     %s\n", st.Version)
	fmt.Fprintf(&b, "  users       %d\n", st.Users)
	fmt.Fprintf(&b, "  clean IPs   %d (refreshed %s)\n", st.CleanIPs.Count, orNever(st.CleanIPs.UpdatedAt))
	fmt.Fprintf(&b, "  backend     %s\n", orNever(st.BackendMode))
	fmt.Fprintf(&b, "  path rotated %s\n", orNever(st.SecurePathRotatedAt))
	fmt.Fprintf(&b, "  panel       %s\n", d.PanelURL())
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: b.String(), Buttons: [][]Button{
		{{Text: "🔗 Links", Data: "w:sub:" + d.Name}, {Text: "➕ Add clean IP", Data: "w:addip:" + d.Name}},
		{{Text: "⚙️ " + d.Name, Data: "w:menu:" + d.Name}, {Text: "🏠 Menu", Data: "home"}},
	}}}}
}

func (r *Router) handleConfigDump(ctx context.Context, in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	cfg, err := r.ops.GetConfig(ctx, d)
	if err != nil {
		return r.reply(in, "Couldn't read config:\n"+errText(err))
	}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	body := string(raw)
	const max = 3500
	if len(body) > max {
		body = body[:max] + "\n… (truncated — open the panel for the full config)"
	}
	return r.reply(in, d.Name+" config:\n"+body)
}

func (r *Router) handleSub(ctx context.Context, in Incoming, args []string) Result {
	d, rest, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	base := d.Origin + "/" + d.SecurePath
	var b strings.Builder
	fmt.Fprintf(&b, "%s — share links\n\n", d.Name)
	if len(rest) >= 1 {
		token := rest[0]
		fmt.Fprintf(&b, "Subscription (user %s):\n%s/sub/%s\n\n", token, base, token)
		fmt.Fprintf(&b, "Import page (QR):\n%s/import/%s\n\n", base, token)
	} else {
		fmt.Fprintf(&b, "Subscription template:\n%s\n\n", d.SubTemplate())
	}
	fmt.Fprintf(&b, "Free config (no token):\n%s/sub/\n", base)
	fmt.Fprintf(&b, "Import page (scannable QR):\n%s/import/\n", base)
	fmt.Fprintf(&b, "Serverless (CF-only fallback):\n%s/sub/?serverless=cf\n", base)
	fmt.Fprintf(&b, "Smart-fragment (DPI bypass):\n%s/sub/?smartfrag=1\n", base)
	return Result{Outs: []Out{{ChatID: in.ChatID, Text: b.String(), Buttons: [][]Button{
		{{Text: "⚙️ " + d.Name, Data: "w:menu:" + d.Name}, {Text: "🏠 Menu", Data: "home"}},
	}}}}
}

func (r *Router) handleRotate(ctx context.Context, in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	fresh, err := r.ops.RotatePath(ctx, d)
	if err != nil {
		return r.reply(in, "Rotate failed:\n"+errText(err))
	}
	_ = r.store.UpdateDeployment(in.UserID, d.Name, func(dd *Deployment) { dd.SecurePath = fresh })
	return r.reply(in, "🔁 Rotated "+d.Name+".\nNew panel: "+d.Origin+"/"+fresh+"/panel\n\nEvery previous URL is dead — re-send subscriptions to your users.")
}

func (r *Router) handleUpdate(ctx context.Context, in Incoming, args []string) Result {
	token, account, errMsg := r.requireCreds(in.UserID)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	if err := r.ops.Update(ctx, token, account, d); err != nil {
		return r.reply(in, "Update failed:\n"+errText(err))
	}
	return r.reply(in, "⬆️ "+d.Name+" re-uploaded with the latest worker build. Config, users and the secret path are preserved.")
}

func (r *Router) handleDestroyAsk(in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	return Result{Outs: []Out{{
		ChatID: in.ChatID,
		Text:   "⚠️ Delete " + d.Name + " at " + d.Origin + "?\nEvery subscription URL it serves stops working immediately.",
		Buttons: [][]Button{{
			{Text: "🗑 Delete", Data: "destroy:" + d.Name},
			{Text: "Cancel", Data: "cancel:"},
		}},
	}}}
}

func (r *Router) doDestroy(ctx context.Context, in Incoming, name string) Result {
	token, account, errMsg := r.requireCreds(in.UserID)
	if errMsg != "" {
		return Result{CallbackAnswer: "No creds.", Outs: []Out{{ChatID: in.ChatID, Text: errMsg}}}
	}
	d, ok := r.store.Deployment(in.UserID, name)
	if !ok {
		return Result{CallbackAnswer: "Gone.", Outs: []Out{{ChatID: in.ChatID, Text: "No worker named " + name + "."}}}
	}
	if err := r.ops.Destroy(ctx, token, account, d, false); err != nil {
		return Result{CallbackAnswer: "Failed.", Outs: []Out{{ChatID: in.ChatID, Text: "Delete failed:\n" + errText(err)}}}
	}
	_ = r.store.RemoveDeployment(in.UserID, name)
	return Result{CallbackAnswer: "Deleted.", Outs: []Out{{ChatID: in.ChatID, Text: "🗑 Deleted " + name + "."}}}
}

func (r *Router) handleDomain(ctx context.Context, in Incoming, args []string) Result {
	token, account, errMsg := r.requireCreds(in.UserID)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	d, rest, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	if len(rest) < 1 {
		return r.reply(in, "Usage: /domain [name] <hostname>\nThe hostname's zone must be in this Cloudflare account.")
	}
	host := strings.TrimSpace(rest[0])
	if err := r.ops.AttachDomain(ctx, token, account, d, host); err != nil {
		return r.reply(in, "Couldn't attach "+host+":\n"+errText(err))
	}
	_ = r.store.UpdateDeployment(in.UserID, d.Name, func(dd *Deployment) { dd.Domain = host })
	return r.reply(in, "🌐 "+host+" attached to "+d.Name+". It may take a moment to go live; then it serves the same subscription as the workers.dev URL.")
}

func (r *Router) handleWarp(ctx context.Context, in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	n, err := r.ops.Warp(ctx, d)
	if err != nil {
		return r.reply(in, "WARP registration failed:\n"+errText(err))
	}
	return r.reply(in, fmt.Sprintf("🛡 Registered %d WARP account(s) and pushed them to %s.\nThe subscription now includes WireGuard + AmneziaWG nodes. Grab the tunnel file with /warpconf.", n, d.Name))
}

func (r *Router) handleWarpConf(ctx context.Context, in Incoming, args []string) Result {
	d, _, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}
	plain, pro, err := r.ops.WarpConf(ctx, d)
	if err != nil {
		return r.reply(in, "Couldn't build the .conf:\n"+errText(err))
	}
	return Result{Outs: []Out{
		{ChatID: in.ChatID, Text: "WireGuard (plain):\n" + plain},
		{ChatID: in.ChatID, Text: "AmneziaWG (obfuscated):\n" + pro},
	}}
}

func orNever(s string) string {
	if strings.TrimSpace(s) == "" {
		return "never"
	}
	return s
}
