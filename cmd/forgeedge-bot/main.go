// Command forgeedge-bot is a standalone Telegram bot that deploys and manages
// ForgeEdge Cloudflare Workers over chat. It is separate from the panel — its
// own process, its own encrypted state — but reuses the panel's internal/edge
// engine, so a Worker it deploys is identical to one the panel deploys.
//
// Configuration is three environment variables:
//
//	FORGEEDGE_BOT_TOKEN   the @BotFather token (required)
//	FORGEEDGE_BOT_OWNER   your Telegram numeric id — the root approver (required)
//	FORGEEDGE_BOT_DATA    state directory (default /var/lib/forgeedge-bot)
//
// Each approved user brings their own Cloudflare credentials with /cf and
// manages only their own Workers.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/forgepanel/forgepanel/internal/edgebot"
	"github.com/forgepanel/forgepanel/internal/version"
)

func main() {
	if versionRequested(os.Args[1:]) {
		fmt.Println(version.String("forgeedge-bot"))
		return
	}

	token := strings.TrimSpace(os.Getenv("FORGEEDGE_BOT_TOKEN"))
	if token == "" {
		fatal("set FORGEEDGE_BOT_TOKEN to your @BotFather bot token")
	}
	owner, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("FORGEEDGE_BOT_OWNER")), 10, 64)
	if err != nil || owner == 0 {
		fatal("set FORGEEDGE_BOT_OWNER to your Telegram numeric id (get it from @userinfobot)")
	}

	dataDir := strings.TrimSpace(os.Getenv("FORGEEDGE_BOT_DATA"))
	if dataDir == "" {
		dataDir = "/var/lib/forgeedge-bot"
	}
	store, err := edgebot.Open(dataDir, owner)
	if err != nil {
		fatal(err.Error())
	}

	bot := edgebot.New(token, store, edgebot.NewOps())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := bot.Run(ctx); err != nil && ctx.Err() == nil {
		fatal(err.Error())
	}
}

func versionRequested(args []string) bool {
	for _, a := range args {
		switch a {
		case "-v", "--version", "version":
			return true
		}
	}
	return false
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "forgeedge-bot: "+msg)
	os.Exit(2)
}
