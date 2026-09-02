// Package edgebot is a standalone Telegram bot that deploys and manages
// ForgeEdge Cloudflare Workers over chat. It reuses the panel's internal/edge
// engine — the same code, the same embedded Worker bundle — so a Worker it
// deploys is byte-for-byte the panel's, but it runs as its own process with no
// panel, no database and no shared state.
//
// Access is request-and-approve: a new person messages the bot, the owner is
// notified and approves, and each approved user brings their own Cloudflare
// credentials and manages only their own Workers.
package edgebot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Status is where a Telegram user sits in the approval lifecycle.
type Status string

const (
	StatusPending  Status = "pending"  // asked to use the bot, awaiting the owner
	StatusApproved Status = "approved" // may bring creds and deploy
	StatusRevoked  Status = "revoked"  // was approved, then cut off
	StatusDenied   Status = "denied"   // request refused
)

// Deployment is one Worker a user owns. FeedPushToken is the machine credential
// the bot presents to the deployed Worker for every action (config, clean-IPs,
// rotate, WARP), so the Worker's admin password is never needed here.
type Deployment struct {
	Name          string `json:"name"`
	Origin        string `json:"origin"`
	SecurePath    string `json:"secure_path"`
	FeedPushToken string `json:"feed_push_token"`
	AccountID     string `json:"account_id"`
	Domain        string `json:"domain,omitempty"`
	CreatedAt     string `json:"created_at"`

	// Recreated records that the deploy had to delete and re-upload the Worker
	// before it would serve. Not persisted: it describes one deploy, not the
	// Worker, and it exists so the reply can say so instead of presenting a
	// second attempt as a clean first-time success.
	Recreated bool `json:"-"`
}

// PanelURL is the Worker's own admin page (for a human, not the bot).
func (d Deployment) PanelURL() string { return d.Origin + "/" + d.SecurePath + "/panel" }

// SubTemplate is the subscription URL with a placeholder for the token.
func (d Deployment) SubTemplate() string { return d.Origin + "/" + d.SecurePath + "/sub/<sub_token>" }

// SharedSub is the tokenless (free-config) subscription.
func (d Deployment) SharedSub() string { return d.Origin + "/" + d.SecurePath + "/sub/" }

// ImportPage is the human-facing share page with scannable QR codes.
func (d Deployment) ImportPage() string { return d.Origin + "/" + d.SecurePath + "/import/" }

// User is one Telegram account known to the bot. CFToken is only ever held here
// in memory and in the AES-GCM-sealed state file on disk; it is never logged.
type User struct {
	ID          int64        `json:"id"`
	Username    string       `json:"username,omitempty"`
	Name        string       `json:"name,omitempty"`
	Status      Status       `json:"status"`
	RequestedAt string       `json:"requested_at,omitempty"`
	DecidedAt   string       `json:"decided_at,omitempty"`
	CFToken     string       `json:"cf_token,omitempty"`
	CFAccount   string       `json:"cf_account,omitempty"`
	Deployments []Deployment `json:"deployments,omitempty"`
}

// HasCreds reports whether the user has stored Cloudflare credentials.
func (u *User) HasCreds() bool { return u.CFToken != "" }

// state is the whole on-disk document.
type state struct {
	Owner int64           `json:"owner"`
	Users map[int64]*User `json:"users"`
}

// Store is the encrypted, concurrency-safe persistence for the bot. Every
// mutation persists the whole file; the file is tiny (a handful of users) so
// there is no reason to track dirty state.
type Store struct {
	mu    sync.Mutex
	path  string
	key   []byte
	state state
}

// Open loads (or creates) the store under dir. owner is the Telegram id of the
// root approver; it is recorded on first creation and refreshed on every open so
// changing FORGEEDGE_BOT_OWNER takes effect on restart.
func Open(dir string, owner int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("edgebot: data dir: %w", err)
	}
	key, err := loadOrCreateKey(filepath.Join(dir, "edgebot.key"))
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:  filepath.Join(dir, "edgebot.state"),
		key:   key,
		state: state{Owner: owner, Users: map[int64]*User{}},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	// The owner is authoritative from the environment, not the file.
	s.state.Owner = owner
	if s.state.Users == nil {
		s.state.Users = map[int64]*User{}
	}
	// The owner is auto-approved everywhere, but the approval flow that creates a
	// user row (Decide) never runs for them — so without this they would have no
	// record to hang credentials or deployments on, and /cf would fail with
	// "unknown user". Materialise an approved row for the owner on every open.
	if owner != 0 {
		if u := s.state.Users[owner]; u == nil {
			s.state.Users[owner] = &User{ID: owner, Status: StatusApproved, RequestedAt: now()}
			if err := s.save(); err != nil {
				return nil, err
			}
		} else if u.Status != StatusApproved {
			u.Status = StatusApproved
			if err := s.save(); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

// loadOrCreateKey returns the 32-byte master key, minting one 0600 on first run.
func loadOrCreateKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		key, derr := base64.StdEncoding.DecodeString(string(raw))
		if derr != nil || len(key) != 32 {
			return nil, fmt.Errorf("edgebot: corrupt key at %s (delete it only if you accept losing stored credentials)", path)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("edgebot: read key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("edgebot: no entropy for master key: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, fmt.Errorf("edgebot: write key: %w", err)
	}
	return key, nil
}

// load decrypts the state file. A missing file is a fresh store, not an error.
func (s *Store) load() error {
	blob, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("edgebot: read state: %w", err)
	}
	if len(blob) == 0 {
		return nil
	}
	plain, err := s.decrypt(blob)
	if err != nil {
		return fmt.Errorf("edgebot: decrypt state (wrong or lost edgebot.key?): %w", err)
	}
	var st state
	if err := json.Unmarshal(plain, &st); err != nil {
		return fmt.Errorf("edgebot: parse state: %w", err)
	}
	s.state = st
	return nil
}

// save encrypts and atomically writes the state. Caller holds s.mu.
func (s *Store) save() error {
	plain, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	blob, err := s.encrypt(plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) encrypt(plain []byte) ([]byte, error) {
	g, err := s.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func (s *Store) decrypt(blob []byte) ([]byte, error) {
	g, err := s.gcm()
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return g.Open(nil, blob[:ns], blob[ns:], nil)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// --- access lifecycle -------------------------------------------------------

// Owner returns the configured owner id.
func (s *Store) Owner() int64 { return s.state.Owner }

// IsOwner reports whether id is the owner.
func (s *Store) IsOwner(id int64) bool { return id == s.state.Owner }

// Lookup returns a copy of a user, or false if unknown.
func (s *Store) Lookup(id int64) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return User{}, false
	}
	return *u, true
}

// IsApproved reports whether id may use the bot (the owner always may).
func (s *Store) IsApproved(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.state.Owner {
		return true
	}
	u := s.state.Users[id]
	return u != nil && u.Status == StatusApproved
}

// RequestOutcome is what EnsureRequest did.
type RequestOutcome int

const (
	RequestNew      RequestOutcome = iota // first time we've seen this user; owner should be told
	RequestPending                        // already pending; still waiting
	RequestApproved                       // already approved
	RequestBlocked                        // denied or revoked
)

// EnsureRequest records a first-time requester as pending and reports what state
// they are in. The owner is auto-approved and never becomes a pending row.
func (s *Store) EnsureRequest(id int64, username, name string) (RequestOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.state.Owner {
		return RequestApproved, nil
	}
	u := s.state.Users[id]
	if u == nil {
		s.state.Users[id] = &User{
			ID: id, Username: username, Name: name,
			Status: StatusPending, RequestedAt: now(),
		}
		return RequestNew, s.save()
	}
	// Keep the display name fresh.
	if username != "" {
		u.Username = username
	}
	if name != "" {
		u.Name = name
	}
	switch u.Status {
	case StatusApproved:
		return RequestApproved, s.save()
	case StatusPending:
		return RequestPending, s.save()
	default:
		return RequestBlocked, s.save()
	}
}

// Decide sets a user's approval status (approve/deny/revoke). Approving an
// unknown id creates the row so the owner can pre-authorise.
func (s *Store) Decide(id int64, status Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		u = &User{ID: id, RequestedAt: now()}
		s.state.Users[id] = u
	}
	u.Status = status
	u.DecidedAt = now()
	return s.save()
}

// SetCreds stores a user's Cloudflare credentials.
func (s *Store) SetCreds(id int64, token, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return fmt.Errorf("unknown user")
	}
	u.CFToken = token
	u.CFAccount = account
	return s.save()
}

// Creds returns a user's stored Cloudflare token and account.
func (s *Store) Creds(id int64) (token, account string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil || u.CFToken == "" {
		return "", "", false
	}
	return u.CFToken, u.CFAccount, true
}

// ListUsers returns copies of every known user, owner-first then by request time.
func (s *Store) ListUsers() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.state.Users))
	for _, u := range s.state.Users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		return out[i].RequestedAt < out[j].RequestedAt
	})
	return out
}

// --- deployments ------------------------------------------------------------

// AddDeployment records a Worker under a user, replacing any with the same name.
func (s *Store) AddDeployment(id int64, d Deployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return fmt.Errorf("unknown user")
	}
	if d.CreatedAt == "" {
		d.CreatedAt = now()
	}
	for i := range u.Deployments {
		if u.Deployments[i].Name == d.Name {
			u.Deployments[i] = d
			return s.save()
		}
	}
	u.Deployments = append(u.Deployments, d)
	return s.save()
}

// Deployments returns copies of a user's Workers.
func (s *Store) Deployments(id int64) []Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return nil
	}
	out := make([]Deployment, len(u.Deployments))
	copy(out, u.Deployments)
	return out
}

// Deployment returns one of a user's Workers by name.
func (s *Store) Deployment(id int64, name string) (Deployment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return Deployment{}, false
	}
	for _, d := range u.Deployments {
		if d.Name == name {
			return d, true
		}
	}
	return Deployment{}, false
}

// UpdateDeployment applies mutate to a stored Worker and persists it. Used to
// record a rotated secure path.
func (s *Store) UpdateDeployment(id int64, name string, mutate func(*Deployment)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return fmt.Errorf("unknown user")
	}
	for i := range u.Deployments {
		if u.Deployments[i].Name == name {
			mutate(&u.Deployments[i])
			return s.save()
		}
	}
	return fmt.Errorf("no worker named %q", name)
}

// RemoveDeployment drops a Worker from a user's list.
func (s *Store) RemoveDeployment(id int64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.state.Users[id]
	if u == nil {
		return fmt.Errorf("unknown user")
	}
	for i := range u.Deployments {
		if u.Deployments[i].Name == name {
			u.Deployments = append(u.Deployments[:i], u.Deployments[i+1:]...)
			return s.save()
		}
	}
	return nil
}
