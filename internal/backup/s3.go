package backup

// Off-box backup delivery to an S3-compatible bucket.
//
// The package comment has advertised local/S3/Telegram since this file's
// neighbours were written, and two of the three existed. A panel that keeps its
// only backups on the machine being backed up has, in the case that matters —
// the disk, the VPS or the provider account going away — no backups at all.
//
// No SDK. A single signed PUT is the whole protocol here, and pulling in an AWS
// SDK for it would add a large dependency surface, a second HTTP client the
// egress proxy does not control, and its own credential-resolution chain that
// would happily pick up an unrelated ~/.aws profile on the host.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
)

// S3Config describes one bucket to ship backups to.
//
// Endpoint is the full base URL rather than a region alias, because the panel is
// most often deployed against something that is not AWS — minio on a second box,
// Backblaze B2, a DigitalOcean Space, an Arvan bucket — and an implementation
// that could only name AWS regions would be useless to nearly everyone running
// it.
type S3Config struct {
	Endpoint  string // https://s3.example.com, https://fra1.digitaloceanspaces.com
	Region    string // SigV4 needs one even where the server ignores it
	Bucket    string
	Prefix    string // optional key prefix, e.g. "panel/"
	AccessKey string
	SecretKey string
	// PathStyle puts the bucket in the path (<endpoint>/<bucket>/<key>) rather
	// than in the hostname. True for minio and most self-hosted gateways, which
	// have no wildcard certificate and no DNS entry per bucket.
	PathStyle bool
}

// defaultS3Region is what an unset region signs with. SigV4 has no "no region"
// encoding: the scope string is mandatory, and every S3-compatible server that
// does not implement regions accepts this one.
const defaultS3Region = "us-east-1"

func (c S3Config) region() string {
	if r := strings.TrimSpace(c.Region); r != "" {
		return r
	}
	return defaultS3Region
}

// Validate reports the first thing missing, naming it, so the settings form can
// say which box is empty instead of "upload failed".
func (c S3Config) Validate() error {
	ep := strings.TrimSpace(c.Endpoint)
	if ep == "" {
		return fmt.Errorf("backup: no S3 endpoint; give the bucket's base URL, e.g. https://s3.example.com")
	}
	u, err := url.Parse(ep)
	if err != nil {
		return fmt.Errorf("backup: S3 endpoint %q is not a URL: %w", ep, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("backup: S3 endpoint %q has no usable scheme; write it as https://host", ep)
	}
	if u.Host == "" {
		return fmt.Errorf("backup: S3 endpoint %q has no host", ep)
	}
	if strings.TrimSpace(c.Bucket) == "" {
		return fmt.Errorf("backup: no S3 bucket")
	}
	if strings.TrimSpace(c.AccessKey) == "" {
		return fmt.Errorf("backup: no S3 access key")
	}
	if strings.TrimSpace(c.SecretKey) == "" {
		return fmt.Errorf("backup: no S3 secret key")
	}
	return nil
}

// Key joins the configured prefix with an object name.
//
// The prefix is trimmed of slashes on both ends: "panel", "/panel/" and
// "panel//" are all the same folder to an operator, and the difference between
// them in a bucket is a second, empty-named directory that nothing lists.
func (c S3Config) Key(base string) string {
	prefix := strings.Trim(strings.TrimSpace(c.Prefix), "/")
	base = strings.TrimLeft(strings.TrimSpace(base), "/")
	if prefix == "" {
		return base
	}
	return prefix + "/" + base
}

// URL is where one object lives.
func (c S3Config) URL(key string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.Endpoint), "/"))
	if err != nil {
		return "", fmt.Errorf("backup: S3 endpoint %q is not a URL: %w", c.Endpoint, err)
	}
	bucket := strings.Trim(strings.TrimSpace(c.Bucket), "/")
	base := strings.TrimRight(u.Path, "/")
	if c.PathStyle {
		u.Path = base + "/" + bucket + "/" + key
	} else {
		u.Host = bucket + "." + u.Host
		u.Path = base + "/" + key
	}
	return u.String(), nil
}

// KeyFingerprint names the key a backup was encrypted under, without revealing
// it.
//
// The manifest is a tar member INSIDE the ciphertext, so an object in a bucket
// cannot say which key opens it. After a master-key rotation a directory of
// .fpbk files is indistinguishable, and a blob nothing can decrypt looks exactly
// like a good one — which is discovered during a restore, the one moment there
// is no time to discover it. The fingerprint therefore has to live outside the
// encrypted bytes, and it rides on the object's metadata.
//
// Domain-separated hash of the DERIVED key, never the master secret and never
// the key itself: 8 bytes is enough to tell two keys apart in a bucket and far
// too little to attack the 32-byte key it names.
func KeyFingerprint(master string) string {
	if strings.TrimSpace(master) == "" {
		return ""
	}
	sum := sha256.Sum256(append([]byte("forgepanel-backup-key-fingerprint\x00"), deriveKey(master)...))
	return hex.EncodeToString(sum[:8])
}

// S3Error is a refusal from the bucket, classified by internal/apierr so the
// three that an operator can actually fix — wrong credentials, no such bucket,
// throttled — arrive as different things instead of one "upload failed".
type S3Error struct {
	// Status is the HTTP status the endpoint answered with, or 0 when there was
	// no answer at all. A DNS failure and a 403 need opposite fixes and both
	// used to read as "the backup did not upload".
	Status  int
	Code    string // the S3 error code, e.g. NoSuchBucket, SignatureDoesNotMatch
	Message string
	Err     error // the transport failure, when Status is 0
}

func (e *S3Error) Error() string {
	switch {
	case e == nil:
		return "backup: S3 error"
	case e.Status == 0:
		return fmt.Sprintf("backup: S3 endpoint unreachable: %s", e.Message)
	case e.Code != "":
		return fmt.Sprintf("backup: S3 refused the upload with %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("backup: S3 refused the upload with %d: %s", e.Status, e.Message)
}

func (e *S3Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// PutObject stores one object with a SigV4-signed PUT.
//
// meta becomes x-amz-meta-<name> headers, and they are set BEFORE signing:
// S3 rejects an x-amz-* header the signature did not cover, so metadata added
// afterwards turns every upload into a 403 that reads like a credential
// problem.
func PutObject(ctx context.Context, c S3Config, key string, blob []byte, meta map[string]string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	endpoint, err := c.URL(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("backup: build the S3 request: %w", err)
	}
	req.ContentLength = int64(len(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range meta {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" || v == "" {
			continue
		}
		req.Header.Set("x-amz-meta-"+name, v)
	}
	sum := sha256.Sum256(blob)
	if err := signV4(c, req, hex.EncodeToString(sum[:]), time.Now()); err != nil {
		return err
	}
	// netegress, never a bare client: on a censored network the panel's own
	// outbound calls are exactly what fails, and a direct dial there times out
	// rather than erroring in any way an operator could read.
	resp, err := netegress.Client(120 * time.Second).Do(req)
	if err != nil {
		return &S3Error{Message: err.Error(), Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s3ErrorBodyLimit))
		return nil
	}
	return readS3Error(resp)
}

// s3ErrorBodyLimit caps how much of a refusal is read. The body is XML from a
// server the operator chose but the panel does not trust to be well behaved, and
// a hostile or broken endpoint must not be able to stream into memory forever on
// a path that is already an error.
const s3ErrorBodyLimit = 8 << 10

func readS3Error(resp *http.Response) *S3Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, s3ErrorBodyLimit))
	out := &S3Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	var parsed struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	if err := xml.Unmarshal(body, &parsed); err == nil && parsed.Code != "" {
		out.Code = parsed.Code
		out.Message = parsed.Message
	}
	if out.Message == "" {
		out.Message = http.StatusText(resp.StatusCode)
	}
	return out
}

// signV4 signs a request with AWS Signature Version 4.
//
// It sets x-amz-date and x-amz-content-sha256 itself and signs `host` plus
// EVERY x-amz-* header already on the request, so a caller cannot accidentally
// send metadata outside the signature.
func signV4(c S3Config, req *http.Request, payloadSHA256 string, now time.Time) error {
	if strings.TrimSpace(c.AccessKey) == "" || strings.TrimSpace(c.SecretKey) == "" {
		return fmt.Errorf("backup: an S3 request cannot be signed without an access key and a secret key")
	}
	stamp := now.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	scope := day + "/" + c.region() + "/s3/aws4_request"

	req.Header.Set("x-amz-date", stamp)
	req.Header.Set("x-amz-content-sha256", payloadSHA256)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	values := map[string]string{"host": host}
	names := []string{"host"}
	for k, v := range req.Header {
		lower := strings.ToLower(k)
		if !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		names = append(names, lower)
		values[lower] = collapseSpace(strings.Join(v, ","))
	}
	sort.Strings(names)

	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(values[n])
		canonicalHeaders.WriteByte('\n')
	}
	signed := strings.Join(names, ";")

	// EscapedPath is what actually goes on the wire, so signing it is signing
	// what the endpoint receives. Re-encoding the decoded path with our own
	// rules would be a second opinion about escaping, and any disagreement
	// between the two shows up only as SignatureDoesNotMatch.
	canonical := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signed,
		payloadSHA256,
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		stamp,
		scope,
		hex.EncodeToString(canonicalHash[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	key = hmacSHA256(key, c.region())
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		strings.TrimSpace(c.AccessKey), scope, signed, signature))
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// canonicalQuery renders the query string the way SigV4 wants it: sorted by
// name, every name and value percent-encoded, empty values kept as "name=".
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// collapseSpace trims a header value and squeezes runs of internal whitespace to
// one space, which is the canonicalisation SigV4 specifies for header values.
func collapseSpace(v string) string {
	return strings.Join(strings.Fields(v), " ")
}
