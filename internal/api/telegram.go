package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/telegram"
)

const gbBytes = 1024 * 1024 * 1024

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

// findUser resolves a username to its record (there is no unique-username lookup
// on the store, so this scans — the user set a Telegram admin manages is small).
func (d tgPanelData) findUser(name string) (*store.User, error) {
	us, err := d.s.db.ListUsers(0)
	if err != nil {
		return nil, err
	}
	for i := range us {
		if us[i].Username == name {
			return &us[i], nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// afterMutation reloads the engines so a change made from Telegram takes effect
// on the running cores immediately, exactly as an edit from the web panel does.
func (d tgPanelData) afterMutation() { d.s.startBackground(d.s.reloadEngines) }

func (d tgPanelData) SetUserStatus(name, status string) error {
	u, err := d.findUser(name)
	if err != nil {
		return err
	}
	switch status {
	case "active":
		u.Status = store.StatusActive
	case "disabled":
		u.Status = store.StatusDisabled
	default:
		return fmt.Errorf("invalid status %q", status)
	}
	if err := d.s.db.SaveUser(u); err != nil {
		return err
	}
	d.afterMutation()
	return nil
}

func (d tgPanelData) ResetUserTraffic(name string) error {
	u, err := d.findUser(name)
	if err != nil {
		return err
	}
	u.LifetimeTraffic += u.UsedTraffic
	u.UsedTraffic = 0
	if u.Status == store.StatusLimited {
		u.Status = store.StatusActive // a quota reset lifts a capped user
	}
	if err := d.s.db.SaveUser(u); err != nil {
		return err
	}
	d.afterMutation()
	return nil
}

func (d tgPanelData) SetUserLimitGB(name string, gb float64) error {
	u, err := d.findUser(name)
	if err != nil {
		return err
	}
	u.DataLimit = int64(gb * gbBytes)
	// A raised (or removed) cap brings a limited user back within budget.
	if u.Status == store.StatusLimited && (u.DataLimit == 0 || u.UsedTraffic < u.DataLimit) {
		u.Status = store.StatusActive
	}
	if err := d.s.db.SaveUser(u); err != nil {
		return err
	}
	d.afterMutation()
	return nil
}

func (d tgPanelData) ExtendUserDays(name string, days int) (string, error) {
	u, err := d.findUser(name)
	if err != nil {
		return "", err
	}
	// Extend from the later of now / current expiry, so a still-valid user keeps
	// their remaining time and an expired one starts fresh from today.
	base := time.Now()
	if u.ExpireAt != nil && u.ExpireAt.After(base) {
		base = *u.ExpireAt
	}
	exp := base.AddDate(0, 0, days)
	u.ExpireAt = &exp
	if u.Status == store.StatusExpired && exp.After(time.Now()) {
		u.Status = store.StatusActive
	}
	if err := d.s.db.SaveUser(u); err != nil {
		return "", err
	}
	d.afterMutation()
	return exp.UTC().Format("2006-01-02"), nil
}

func (d tgPanelData) CreateUser(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("username required")
	}
	if _, err := d.findUser(name); err == nil {
		return "", fmt.Errorf("user %q already exists", name)
	}
	pw, _ := keygen.Password(16)
	u := &store.User{
		Username: name, Status: store.StatusActive,
		UUID: keygen.UUID(), Password: pw, SubToken: token26(),
	}
	if err := d.s.db.CreateUser(u); err != nil {
		return "", err
	}
	d.afterMutation()
	return u.SubToken, nil
}

func (d tgPanelData) DeleteUser(name string) error {
	u, err := d.findUser(name)
	if err != nil {
		return err
	}
	if err := d.s.db.DeleteUser(u.ID); err != nil {
		return err
	}
	d.afterMutation()
	return nil
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
