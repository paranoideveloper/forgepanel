package webhook

// Proving a delivery came from this panel.
//
// A webhook URL is an unauthenticated public endpoint. If the receiver acts on
// the body — suspends an account, opens a ticket, pages someone — then without
// a signature anyone who learns the URL has been handed a remote control over
// that action, and the URL leaks the ordinary ways: a proxy log, a screenshot,
// a copied-and-pasted support message.
//
// The timestamp is inside the MAC rather than beside it. Signing the body alone
// makes a captured delivery replayable for ever; a receiver that checks the age
// of a signed timestamp can bound that window. Both halves are needed — signing
// the timestamp without the body would let anyone re-use a stolen signature on
// a body of their choosing.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

const (
	// HeaderSignature carries `t=<unix>,v1=<hex>`. The scheme is versioned in
	// the value so a future digest can be added alongside v1 rather than
	// breaking every deployed receiver on the day it ships.
	HeaderSignature = "X-ForgePanel-Signature"
	// HeaderEvent lets a receiver route without parsing the body, which is what
	// makes a two-line handler in someone's automation tool possible.
	HeaderEvent = "X-ForgePanel-Event"
	// HeaderDelivery repeats across an event's retries so a receiver can drop a
	// duplicate it has already handled.
	HeaderDelivery = "X-ForgePanel-Delivery"
)

// Sign returns the X-ForgePanel-Signature value for a body at a given time.
//
// The signed message is `<unix>.<body>` — the separator matters: without it, a
// timestamp of 12 and a body starting "3" would sign identically to a timestamp
// of 123 and a body starting one byte later.
func Sign(secret string, ts int64, body []byte) string {
	stamp := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + stamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
