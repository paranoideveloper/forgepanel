package dns

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	requireNoError(t, err)
	enc, err := NewAESGCM(key)
	requireNoError(t, err)

	plaintext := []byte(`{"api_token":"super-secret"}`)
	blob, err := enc.Encrypt(plaintext)
	requireNoError(t, err)
	if bytes.Contains(blob, []byte("super-secret")) {
		t.Fatal("the ciphertext must not contain the plaintext")
	}
	got, err := enc.Decrypt(blob)
	requireNoError(t, err)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip changed the value: %q", got)
	}

	// The nonce is random, so the same plaintext must not produce the same blob.
	blob2, err := enc.Encrypt(plaintext)
	requireNoError(t, err)
	if bytes.Equal(blob, blob2) {
		t.Fatal("encrypting twice must not produce identical ciphertext")
	}
}

func TestAESGCMRejectsWrongKey(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	e1, err := NewAESGCM(k1)
	requireNoError(t, err)
	e2, err := NewAESGCM(k2)
	requireNoError(t, err)

	blob, err := e1.Encrypt([]byte("secret"))
	requireNoError(t, err)
	_, err = e2.Decrypt(blob)
	e := requireKind(t, err, KindAuth)
	requireContains(t, e.Remediation, "master key changed", "wrong key remediation")
}

// GCM authenticates: a flipped byte must fail rather than decrypt to garbage.
func TestAESGCMDetectsTampering(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	blob, err := enc.Encrypt([]byte("secret"))
	requireNoError(t, err)
	blob[len(blob)-1] ^= 0xff
	_, err = enc.Decrypt(blob)
	requireKind(t, err, KindAuth)
}

func TestAESGCMRejectsShortCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESGCM(key)
	_, err := enc.Decrypt([]byte("tiny"))
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "register it again", "short ciphertext remediation")
}

func TestNewAESGCMKeySizes(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		if _, err := NewAESGCM(make([]byte, size)); err != nil {
			t.Fatalf("%d-byte key rejected: %v", size, err)
		}
	}
	_, err := NewAESGCM(make([]byte, 20))
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "16, 24 or 32", "bad key size message")
}

func TestNewAESGCMFromPassphrase(t *testing.T) {
	enc, err := NewAESGCMFromPassphrase("panel-master-key")
	requireNoError(t, err)
	blob, err := enc.Encrypt([]byte("x"))
	requireNoError(t, err)

	// The same passphrase derives the same key, so a restart still decrypts.
	again, err := NewAESGCMFromPassphrase("panel-master-key")
	requireNoError(t, err)
	got, err := again.Decrypt(blob)
	requireNoError(t, err)
	if string(got) != "x" {
		t.Fatalf("unexpected round trip: %q", got)
	}

	_, err = NewAESGCMFromPassphrase("   ")
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "never stored in plaintext", "empty passphrase remediation")
}

func TestKeyEncoding(t *testing.T) {
	key, err := GenerateKey()
	requireNoError(t, err)
	decoded, err := DecodeKey(EncodeKey(key))
	requireNoError(t, err)
	if !bytes.Equal(key, decoded) {
		t.Fatal("key encoding did not round trip")
	}
	_, err = DecodeKey("not base64!!!")
	requireKind(t, err, KindValidation)
}

func newTestCredentialStore(t *testing.T) (*CredentialStore, *MemStore) {
	t.Helper()
	key, err := GenerateKey()
	requireNoError(t, err)
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	repo := NewMemStore()
	store, err := NewCredentialStore(repo, enc)
	requireNoError(t, err)
	store.now = fixedNow(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC))
	return store, repo
}

func TestCredentialStoreEncryptsAtRest(t *testing.T) {
	store, repo := newTestCredentialStore(t)

	rec, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "super-secret-token"})
	requireNoError(t, err)
	if rec.Secret != nil {
		t.Fatal("the returned metadata must never carry secret material")
	}

	// The bytes actually on disk must not contain the token.
	raw, err := repo.GetCredential("cf1")
	requireNoError(t, err)
	if bytes.Contains(raw.Secret, []byte("super-secret-token")) {
		t.Fatal("the stored blob contains the plaintext token")
	}

	creds, meta, err := store.Get("cf1")
	requireNoError(t, err)
	if creds.Get("api_token") != "super-secret-token" {
		t.Fatalf("unexpected decrypted value: %q", creds.Get("api_token"))
	}
	if meta.Provider != "cloudflare" || meta.Label != "main" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
}

// There is deliberately no plaintext fallback: a store without an encryptor
// must refuse to exist.
func TestCredentialStoreRequiresAnEncryptor(t *testing.T) {
	_, err := NewCredentialStore(NewMemStore(), nil)
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "never stored in plaintext", "missing encryptor remediation")

	_, err = NewCredentialStore(nil, nil)
	requireKind(t, err, KindValidation)
}

func TestCredentialStoreValidatesRequiredFields(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	_, err := store.Put("cf1", "cloudflare", "main", Credentials{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "api_token", "missing required field")

	_, err = store.Put("x", "no-such-provider", "", Credentials{})
	e = requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "cloudflare", "unknown provider lists the real ones")
}

func TestCredentialStoreListHidesSecrets(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	_, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "t1"})
	requireNoError(t, err)
	_, err = store.Put("ds1", "desec", "backup", Credentials{"token": "t2"})
	requireNoError(t, err)

	list, err := store.List()
	requireNoError(t, err)
	if len(list) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(list))
	}
	for _, rec := range list {
		if rec.Secret != nil {
			t.Fatalf("credential %q leaked its secret in a listing", rec.ID)
		}
	}
}

func TestCredentialStorePreservesCreatedAtOnUpdate(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	first, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "t1"})
	requireNoError(t, err)

	store.now = fixedNow(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	second, err := store.Put("cf1", "cloudflare", "renamed", Credentials{"api_token": "t2"})
	requireNoError(t, err)
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("updating must preserve CreatedAt: %v vs %v", second.CreatedAt, first.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updating must advance UpdatedAt: %v vs %v", second.UpdatedAt, first.UpdatedAt)
	}
	creds, _, err := store.Get("cf1")
	requireNoError(t, err)
	if creds.Get("api_token") != "t2" {
		t.Fatalf("the update did not replace the secret: %q", creds.Get("api_token"))
	}
}

func TestCredentialStoreGenerateID(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	rec, err := store.Put("", "cloudflare", "auto", Credentials{"api_token": "t"})
	requireNoError(t, err)
	if len(rec.ID) != 12 {
		t.Fatalf("expected a generated 12-character id, got %q", rec.ID)
	}
}

func TestCredentialStoreDeleteAndMissing(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	_, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "t"})
	requireNoError(t, err)
	requireNoError(t, store.Delete("cf1"))

	_, _, err = store.Get("cf1")
	e := requireKind(t, err, KindNotFound)
	requireContains(t, e.Remediation, "list credentials", "missing credential remediation")
}

func TestCredentialStoreBuildsProvider(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	_, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "t"})
	requireNoError(t, err)

	p, meta, err := store.Provider("cf1")
	requireNoError(t, err)
	if p.Name() != "cloudflare" || meta.Provider != "cloudflare" {
		t.Fatalf("unexpected provider: %+v %+v", p, meta)
	}

	// A registered-but-unbuilt provider must produce the typed error.
	_, err = store.Put("do1", "digitalocean", "", Credentials{"api_token": "t"})
	requireNoError(t, err)
	_, _, err = store.Provider("do1")
	requireKind(t, err, KindNotImplemented)
}

func TestCredentialStoreRecordsVerification(t *testing.T) {
	store, _ := newTestCredentialStore(t)
	_, err := store.Put("cf1", "cloudflare", "main", Credentials{"api_token": "t"})
	requireNoError(t, err)

	requireNoError(t, store.RecordVerification("cf1", errors.New("token rejected")))
	list, err := store.List()
	requireNoError(t, err)
	if list[0].LastVerifyError != "token rejected" || list[0].LastVerifiedAt != nil {
		t.Fatalf("a failed verification must be recorded: %+v", list[0])
	}

	requireNoError(t, store.RecordVerification("cf1", nil))
	list, err = store.List()
	requireNoError(t, err)
	if list[0].LastVerifyError != "" || list[0].LastVerifiedAt == nil {
		t.Fatalf("a successful verification must clear the error: %+v", list[0])
	}

	err = store.RecordVerification("missing", nil)
	requireKind(t, err, KindNotFound)
}

// The AAD binds a blob to this package, so a blob encrypted for another purpose
// under the same key does not decrypt here.
func TestCredentialAADIsBound(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	if !strings.Contains(string(credentialAAD), "internal/dns") {
		t.Fatalf("the AAD must name its purpose, got %q", credentialAAD)
	}
	blob, err := enc.Encrypt([]byte("x"))
	requireNoError(t, err)
	got, err := enc.Decrypt(blob)
	requireNoError(t, err)
	if string(got) != "x" {
		t.Fatalf("unexpected round trip: %q", got)
	}
}

func TestCredentialsRequireNamesEveryMissingFieldAtOnce(t *testing.T) {
	err := Credentials{}.Require("namecheap", "api_user", "api_key", "client_ip")
	e := requireKind(t, err, KindValidation)
	for _, field := range []string{"api_user", "api_key", "client_ip"} {
		requireContains(t, e.Message, field, "missing field list")
	}
}
