package api

import (
	"context"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/telegram"
)

// tgPanelData adapts the store to the bot's read-only PanelData interface.
type tgPanelData struct{ s *Server }

func (d tgPanelData) Stats() (int, int, int) {
	ins, _ := d.s.db.ListInbounds()
	us, _ := d.s.db.ListUsers(0)
	gs, _ := d.s.db.ListGroups()
	return len(ins), len(us), len(gs)
}

func (d tgPanelData) UserByName(name string) (string, string, float64, float64, bool) {
	us, _ := d.s.db.ListUsers(0)
	for _, u := range us {
		if u.Username == name {
			const gb = 1024 * 1024 * 1024
			return u.Username, string(u.Status), float64(u.UsedTraffic) / gb, float64(u.DataLimit) / gb, true
		}
	}
	return "", "", 0, 0, false
}

func (d tgPanelData) SubURLForToken(token string) (string, bool) {
	if _, err := d.s.db.UserBySubToken(token); err != nil {
		return "", false
	}
	return "/sub/" + token, true
}

// startBot launches the Telegram bot if a token is configured (spec §13).
func (s *Server) startBot(ctx context.Context) {
	if s.cfg.TelegramToken == "" {
		return
	}
	var ids []int64
	for _, p := range strings.Split(s.cfg.TelegramAdmins, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	bot := telegram.New(s.cfg.TelegramToken, ids, tgPanelData{s})
	go bot.Run(ctx)
}
