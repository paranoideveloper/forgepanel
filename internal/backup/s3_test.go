package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The credentials and the clock are fixed so the signature is reproducible.
// They are not anyone's keys.
func fixtureS3() S3Config {
	return S3Config{
		Endpoint:  "https://s3.example.com",
		Region:    "us-east-1",
		Bucket:    "fp",
		Prefix:    "panel/",
		AccessKey: "AKIAFIXTURE",
		SecretKey: "s3cr3tfixture",
		PathStyle: true,
	}
}

var fixtureClock = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// An unsigned PUT is accepted by a bucket that allows anonymous writes and
// refused by every other one, so "it worked on my minio" is exactly how an
// unsigned uploader ships. These assertions are about the Authorization header
// the request actually carries.
func TestPutObjectSignsWithSigV4(t *testing.T) {
	c := fixtureS3()
	url, err := c.URL(c.Key("forgepanel-20260830-120000.fpbk"))
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	if want := "https://s3.example.com/fp/panel/forgepanel-20260830-120000.fpbk"; url != want {
		t.Fatalf("URL = %q, want %q", url, want)
	}

	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Independently verified: printf '' | sha256sum.
	const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(sha256Sum(nil)); got != emptySHA {
		t.Fatalf("sha256 of the empty payload = %q, want %q", got, emptySHA)
	}

	if err := signV4(c, req, emptySHA, fixtureClock); err != nil {
		t.Fatalf("signV4: %v", err)
	}

	if got := req.Header.Get("x-amz-date"); got != "20260830T120000Z" {
		t.Errorf("x-amz-date = %q, want %q", got, "20260830T120000Z")
	}
	if got := req.Header.Get("x-amz-content-sha256"); got != emptySHA {
		t.Errorf("x-amz-content-sha256 = %q, want the empty-payload digest", got)
	}

	auth := req.Header.Get("Authorization")
	const wantCred = "AWS4-HMAC-SHA256 Credential=AKIAFIXTURE/20260830/us-east-1/s3/aws4_request,"
	if !strings.HasPrefix(auth, wantCred) {
		t.Errorf("Authorization = %q,\nwant it to start with %q", auth, wantCred)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date,") {
		t.Errorf("Authorization = %q, want SignedHeaders=host;x-amz-content-sha256;x-amz-date", auth)
	}
	sig := regexp.MustCompile(`Signature=([0-9a-f]{64})$`).FindStringSubmatch(auth)
	if sig == nil {
		t.Fatalf("Authorization = %q, want it to end in 64 lowercase hex of signature", auth)
	}
	// A PIN, and deliberately not presented as an AWS-published vector: it was
	// derived from the SigV4 specification by a second, independent
	// implementation and cross-checked against this one. It is here because a
	// refactor of the canonical request can leave a signature that still parses
	// while covering different bytes, and the only symptom of that is a
	// SignatureDoesNotMatch from a bucket nobody is watching.
	const pinned = "48d9f3b2c31be436c95af725a6760cd3296f94ef92c9a4897bdef5f2c0f16cf2"
	if sig[1] != pinned {
		t.Errorf("signature = %q, want the pinned %q", sig[1], pinned)
	}
}

// Metadata must be SIGNED, not merely sent: S3 rejects an x-amz-* header that
// was not covered by the signature, so a fingerprint added after signing turns
// every upload into a 403.
func TestObjectMetadataIsCoveredByTheSignature(t *testing.T) {
	c := fixtureS3()
	req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/fp/panel/x.fpbk", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-amz-meta-key-fingerprint", "0123456789abcdef")

	if err := signV4(c, req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fixtureClock); err != nil {
		t.Fatalf("signV4: %v", err)
	}
	auth := req.Header.Get("Authorization")
	const want = "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-key-fingerprint,"
	if !strings.Contains(auth, want) {
		t.Errorf("Authorization = %q, want %q", auth, want)
	}
}

// The manifest lives INSIDE the ciphertext, so a bucket full of .fpbk objects
// cannot say which key opens which one. After a master-key rotation an
// unrestorable blob looks exactly like a good one.
func TestKeyFingerprintIdentifiesTheKeyWithoutRevealingIt(t *testing.T) {
	a := KeyFingerprint("master-one")
	b := KeyFingerprint("master-two")
	if a == "" || b == "" {
		t.Fatalf("fingerprints are empty (%q, %q)", a, b)
	}
	if a == b {
		t.Errorf("two different master keys fingerprint the same: %q", a)
	}
	if a != KeyFingerprint("master-one") {
		t.Error("the fingerprint is not stable for one key")
	}
	if strings.Contains(a, "master-one") {
		t.Errorf("the fingerprint %q carries the key itself", a)
	}
	// A derived key is 32 bytes; the fingerprint must be a short, non-secret
	// prefix of a hash of it, never the key material.
	if len(a) != 16 {
		t.Errorf("fingerprint %q is %d chars, want 16", a, len(a))
	}
	if KeyFingerprint("  ") != "" {
		t.Error("a blank master key produced a fingerprint")
	}
}

func TestValidateNamesTheMissingField(t *testing.T) {
	base := fixtureS3()
	for _, tc := range []struct {
		name string
		mut  func(*S3Config)
		want string
	}{
		{"no endpoint", func(c *S3Config) { c.Endpoint = "" }, "endpoint"},
		{"no bucket", func(c *S3Config) { c.Bucket = "" }, "bucket"},
		{"no access key", func(c *S3Config) { c.AccessKey = "" }, "access key"},
		{"no secret key", func(c *S3Config) { c.SecretKey = "" }, "secret key"},
		{"not a URL", func(c *S3Config) { c.Endpoint = "s3.example.com" }, "scheme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Errorf("a complete config was refused: %v", err)
	}
}

// A prefix an operator typed with or without slashes must produce the same key:
// "panel" and "/panel/" both mean the same folder, and a doubled or leading
// slash creates a second, empty-named folder in the bucket.
func TestKeyJoinsThePrefixWithoutDoublingSlashes(t *testing.T) {
	for _, tc := range []struct{ prefix, want string }{
		{"", "a.fpbk"},
		{"panel", "panel/a.fpbk"},
		{"panel/", "panel/a.fpbk"},
		{"/panel/", "panel/a.fpbk"},
		{"panel//", "panel/a.fpbk"},
	} {
		c := fixtureS3()
		c.Prefix = tc.prefix
		if got := c.Key("a.fpbk"); got != tc.want {
			t.Errorf("prefix %q: key = %q, want %q", tc.prefix, got, tc.want)
		}
	}
}

func TestVirtualHostStyleURLPutsTheBucketInTheHost(t *testing.T) {
	c := fixtureS3()
	c.PathStyle = false
	got, err := c.URL("panel/a.fpbk")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://fp.s3.example.com/panel/a.fpbk"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
