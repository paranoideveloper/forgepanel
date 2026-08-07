package dns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Encryptor protects credential material at rest. The panel supplies the
// implementation (and therefore the key) so this package never decides where a
// master key lives.
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// aesGCM is the default AES-256-GCM implementation. The nonce is prepended to
// the ciphertext, and the AAD binds the blob to this package so a credential
// blob cannot be replayed into another consumer of the same key.
type aesGCM struct {
	aead cipher.AEAD
}

// credentialAAD binds ciphertext to its purpose.
var credentialAAD = []byte("forgepanel/internal/dns:credential:v1")

// NewAESGCM builds an Encryptor from a raw key of 16, 24 or 32 bytes.
func NewAESGCM(key []byte) (Encryptor, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, &Error{Op: "new-encryptor", Kind: KindValidation,
			Message:     fmt.Sprintf("AES key must be 16, 24 or 32 bytes, got %d", len(key)),
			Remediation: "pass the panel master key (32 bytes), or derive one with NewAESGCMFromPassphrase"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &Error{Op: "new-encryptor", Kind: KindValidation,
			Message: "could not create the AES cipher: " + err.Error(), Cause: err}
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &Error{Op: "new-encryptor", Kind: KindValidation,
			Message: "could not create the GCM mode: " + err.Error(), Cause: err}
	}
	return &aesGCM{aead: aead}, nil
}

// NewAESGCMFromPassphrase derives a 32-byte key from an arbitrary secret. It is
// the convenience path for a panel whose master key is stored as a string; a
// caller holding real key bytes should use NewAESGCM directly.
func NewAESGCMFromPassphrase(secret string) (Encryptor, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, &Error{Op: "new-encryptor", Kind: KindValidation,
			Message:     "the encryption secret is empty",
			Remediation: "credentials are never stored in plaintext; supply the panel master key"}
	}
	sum := sha256.Sum256([]byte(secret))
	return NewAESGCM(sum[:])
}

func (a *aesGCM) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, &Error{Op: "encrypt", Kind: KindServer,
			Message: "could not read cryptographic randomness: " + err.Error(), Cause: err}
	}
	return a.aead.Seal(nonce, nonce, plaintext, credentialAAD), nil
}

func (a *aesGCM) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := a.aead.NonceSize()
	if len(ciphertext) < ns+a.aead.Overhead() {
		return nil, &Error{Op: "decrypt", Kind: KindValidation,
			Message:     "the stored credential is too short to be valid ciphertext",
			Remediation: "the record is corrupt; delete the credential and register it again"}
	}
	plaintext, err := a.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], credentialAAD)
	if err != nil {
		return nil, &Error{Op: "decrypt", Kind: KindAuth,
			Message:     "could not decrypt the stored credential",
			Remediation: "this almost always means the panel master key changed. Restore the original key, or delete the credential and register it again.",
			Cause:       err}
	}
	return plaintext, nil
}

// CredentialRecord is the at-rest row: everything except Secret is plaintext
// metadata so the UI can list credentials without decrypting anything.
type CredentialRecord struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Label     string    `json:"label"`
	Secret    []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// LastVerifiedAt and LastVerifyError record the outcome of the most recent
	// VerifyCredentials call, so a token that expired last week is visible in
	// the list rather than discovered mid-provision.
	LastVerifiedAt  *time.Time `json:"last_verified_at,omitempty"`
	LastVerifyError string     `json:"last_verify_error,omitempty"`
}

// CredentialRepo is the persistence the credential store needs. The panel
// supplies it; a GORM-backed implementation ships in gormstore.go and an
// in-memory one in memstore.go.
type CredentialRepo interface {
	PutCredential(rec CredentialRecord) error
	GetCredential(id string) (*CredentialRecord, error)
	ListCredentials() ([]CredentialRecord, error)
	DeleteCredential(id string) error
}

// CredentialStore encrypts credentials on the way in and decrypts on the way
// out. Nothing else in this package reads CredentialRecord.Secret directly.
type CredentialStore struct {
	repo CredentialRepo
	enc  Encryptor
	now  func() time.Time
}

// NewCredentialStore wires a repo and encryptor together. Both are required —
// there is deliberately no plaintext fallback.
func NewCredentialStore(repo CredentialRepo, enc Encryptor) (*CredentialStore, error) {
	if repo == nil {
		return nil, &Error{Op: "new-credential-store", Kind: KindValidation,
			Message: "no credential repository was supplied", Remediation: "pass Deps.Credentials"}
	}
	if enc == nil {
		return nil, &Error{Op: "new-credential-store", Kind: KindValidation,
			Message:     "no encryptor was supplied",
			Remediation: "credentials are never stored in plaintext; pass Deps.Encryptor (see NewAESGCM)"}
	}
	return &CredentialStore{repo: repo, enc: enc, now: time.Now}, nil
}

// Put encrypts and stores a credential, returning the metadata row.
func (s *CredentialStore) Put(id, provider, label string, creds Credentials) (*CredentialRecord, error) {
	info, ok := Lookup(provider)
	if !ok {
		return nil, &Error{Op: "put-credential", Kind: KindValidation,
			Message:     fmt.Sprintf("unknown DNS provider %q", provider),
			Remediation: "use one of: " + strings.Join(providerNames(), ", ")}
	}
	var required []string
	for _, f := range info.CredentialFields {
		if f.Required {
			required = append(required, f.Key)
		}
	}
	if err := creds.Require(info.Name, required...); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return nil, &Error{Op: "put-credential", Kind: KindValidation,
			Message: "could not encode the credential: " + err.Error(), Cause: err}
	}
	blob, err := s.enc.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		id, err = RandomLabel(12)
		if err != nil {
			return nil, err
		}
	}
	now := s.now().UTC()
	rec := CredentialRecord{
		ID: id, Provider: info.Name, Label: strings.TrimSpace(label),
		Secret: blob, CreatedAt: now, UpdatedAt: now,
	}
	if existing, err := s.repo.GetCredential(id); err == nil && existing != nil {
		rec.CreatedAt = existing.CreatedAt
	}
	if err := s.repo.PutCredential(rec); err != nil {
		return nil, wrapRepoError("put-credential", err)
	}
	out := rec
	out.Secret = nil
	return &out, nil
}

// Get decrypts a credential.
func (s *CredentialStore) Get(id string) (Credentials, *CredentialRecord, error) {
	rec, err := s.repo.GetCredential(id)
	if err != nil {
		return nil, nil, wrapRepoError("get-credential", err)
	}
	if rec == nil {
		return nil, nil, &Error{Op: "get-credential", Kind: KindNotFound,
			Message:     fmt.Sprintf("no stored DNS credential with id %q", id),
			Remediation: "list credentials to find the right id, or register the credential first"}
	}
	plaintext, err := s.enc.Decrypt(rec.Secret)
	if err != nil {
		return nil, nil, err
	}
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, nil, &Error{Op: "get-credential", Kind: KindValidation,
			Message:     "the stored credential decrypted but is not valid JSON",
			Remediation: "delete the credential and register it again", Cause: err}
	}
	meta := *rec
	meta.Secret = nil
	return creds, &meta, nil
}

// List returns credential metadata with no secret material.
func (s *CredentialStore) List() ([]CredentialRecord, error) {
	recs, err := s.repo.ListCredentials()
	if err != nil {
		return nil, wrapRepoError("list-credentials", err)
	}
	for i := range recs {
		recs[i].Secret = nil
	}
	return recs, nil
}

// Delete removes a credential.
func (s *CredentialStore) Delete(id string) error {
	if err := s.repo.DeleteCredential(id); err != nil {
		return wrapRepoError("delete-credential", err)
	}
	return nil
}

// Provider builds a live provider from a stored credential.
func (s *CredentialStore) Provider(id string) (Provider, *CredentialRecord, error) {
	creds, meta, err := s.Get(id)
	if err != nil {
		return nil, nil, err
	}
	p, err := NewProvider(meta.Provider, creds)
	if err != nil {
		return nil, meta, err
	}
	return p, meta, nil
}

// RecordVerification stamps the outcome of a verification onto the stored row.
func (s *CredentialStore) RecordVerification(id string, verifyErr error) error {
	rec, err := s.repo.GetCredential(id)
	if err != nil {
		return wrapRepoError("record-verification", err)
	}
	if rec == nil {
		return &Error{Op: "record-verification", Kind: KindNotFound,
			Message: fmt.Sprintf("no stored DNS credential with id %q", id)}
	}
	now := s.now().UTC()
	rec.UpdatedAt = now
	if verifyErr != nil {
		rec.LastVerifyError = verifyErr.Error()
		rec.LastVerifiedAt = nil
	} else {
		rec.LastVerifyError = ""
		rec.LastVerifiedAt = &now
	}
	if err := s.repo.PutCredential(*rec); err != nil {
		return wrapRepoError("record-verification", err)
	}
	return nil
}

func providerNames() []string {
	infos := Providers()
	out := make([]string, 0, len(infos))
	for _, i := range infos {
		out = append(out, i.Name)
	}
	return out
}

func wrapRepoError(op string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := AsError(err); ok {
		return err
	}
	return &Error{Op: op, Kind: KindServer,
		Message:     "the credential store failed: " + err.Error(),
		Remediation: "check the panel database is writable and not out of disk",
		Cause:       err}
}

// EncodeKey renders a key for storage in a config file.
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodeKey parses a base64 key produced by EncodeKey.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, &Error{Op: "decode-key", Kind: KindValidation,
			Message:     "the encryption key is not valid base64: " + err.Error(),
			Remediation: "store the key exactly as EncodeKey produced it", Cause: err}
	}
	return key, nil
}

// GenerateKey returns a fresh 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, &Error{Op: "generate-key", Kind: KindServer,
			Message: "could not read cryptographic randomness: " + err.Error(), Cause: err}
	}
	return key, nil
}
