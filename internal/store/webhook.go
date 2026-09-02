package store

// Outbound webhook receivers: where the panel posts lifecycle events.

import "time"

// WebhookEndpoint is one operator-owned receiver.
type WebhookEndpoint struct {
	Base
	URL string `gorm:"not null" json:"url"`
	// Secret signs every delivery. It is a bearer credential in both
	// directions — anyone holding it can forge a delivery the receiver will
	// believe — so it is never echoed back out of the API.
	Secret string `json:"-"`
	// Events is the comma-separated subscribed type list. EMPTY MEANS
	// EVERYTHING: an endpoint that is configured, enabled and silent because
	// nobody ticked a box is the worst of the available defaults.
	Events   string `json:"events"`
	Enabled  bool   `gorm:"default:true" json:"enabled"`
	ProxyURL string `json:"proxy_url"`

	// The last attempt's outcome, kept so the settings page can say "answered
	// 401 four hours ago" instead of leaving the operator to conclude the panel
	// never sends anything.
	LastStatus  int        `json:"last_status"`
	LastError   string     `json:"last_error"`
	LastAttempt *time.Time `json:"last_attempt"`
}

// ListWebhooks returns every endpoint, oldest first.
func (s *Store) ListWebhooks() ([]WebhookEndpoint, error) {
	var out []WebhookEndpoint
	err := s.db.Order("id asc").Find(&out).Error
	return out, err
}

// WebhookByID loads one endpoint.
func (s *Store) WebhookByID(id uint) (*WebhookEndpoint, error) {
	var w WebhookEndpoint
	if err := s.db.First(&w, id).Error; err != nil {
		return nil, err
	}
	return &w, nil
}

// CreateWebhook persists an endpoint.
func (s *Store) CreateWebhook(w *WebhookEndpoint) error {
	// GORM omits zero values on INSERT when the column declares a default, so an
	// endpoint created disabled would be stored ENABLED — and an enabled
	// endpoint starts receiving every event the panel raises.
	wantEnabled := w.Enabled
	if err := s.db.Create(w).Error; err != nil {
		return err
	}
	if !wantEnabled {
		return s.db.Model(w).UpdateColumn("enabled", false).Error
	}
	return nil
}

// SaveWebhook updates an endpoint.
func (s *Store) SaveWebhook(w *WebhookEndpoint) error {
	return s.db.Model(w).Select("*").Omit("created_at").Updates(w).Error
}

// RecordWebhookAttempt stamps the outcome of one delivery attempt.
//
// It writes the three columns by hand rather than through SaveWebhook because
// it runs on the delivery goroutine, minutes after the row was read: a
// full-row save would resurrect whatever the operator has edited in the
// meantime, including a secret they just rotated.
func (s *Store) RecordWebhookAttempt(id uint, status int, errText string, at time.Time) error {
	return s.db.Model(&WebhookEndpoint{}).Where("id = ?", id).Updates(map[string]any{
		"last_status":  status,
		"last_error":   errText,
		"last_attempt": at,
	}).Error
}

// DeleteWebhook removes an endpoint.
func (s *Store) DeleteWebhook(id uint) error {
	return s.db.Delete(&WebhookEndpoint{}, id).Error
}
