package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

const gbBytes = 1024 * 1024 * 1024

// tgPanelData adapts the store to the bot's read-only PanelData interface.
type tgPanelData struct{ s *Server }

func (d tgPanelData) Stats() (int, int, int) {
	ins, us, gs, err := d.s.db.Counts()
	if err != nil {
		return 0, 0, 0
	}
	return int(ins), int(us), int(gs)
}

func (d tgPanelData) UserByName(name string) (string, string, float64, float64, bool) {
	u, err := d.s.db.UserByUsername(name)
	if err != nil {
		return "", "", 0, 0, false
	}
	const gb = 1024 * 1024 * 1024
	return u.Username, string(u.Status), float64(u.UsedTraffic) / gb, float64(u.DataLimit) / gb, true
}

func (d tgPanelData) SubURLForToken(token string) (string, bool) {
	if _, err := d.s.db.UserBySubToken(token); err != nil {
		return "", false
	}
	return "/sub/" + token, true
}

// findUser resolves a username to its record through the unique index.
func (d tgPanelData) findUser(name string) (*store.User, error) {
	u, err := d.s.db.UserByUsername(name)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
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

// MakeBackup implements telegram.BackupProvider so the bot's /backup command has
// something to send.
//
// It takes a fresh backup rather than shipping the newest file on disk: an
// operator asking for one over Telegram is usually reacting to something, and
// yesterday's copy is not what they mean.
func (d tgPanelData) MakeBackup() (string, []byte, error) {
	master := d.s.masterKey()
	if master == "" {
		return "", nil, fmt.Errorf("this data directory has no master key, so nothing can be encrypted")
	}
	files := backup.PanelFiles(d.s.cfg.DataDir)
	blob, err := backup.CreateWithManifest(master, d.s.cfg.DataDir, files, d.s.backupManifest())
	if err != nil {
		return "", nil, err
	}
	name := fmt.Sprintf("forgepanel-%s.fpbk", time.Now().UTC().Format("20060102-150405"))
	return name, blob, nil
}
