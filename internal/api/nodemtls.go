package api

// The mTLS control plane between the panel and its nodes.
//
// What this replaces: the enrolment token was a node's entire identity, for
// good. It was returned in an API response body, embedded in a `curl … | bash`
// command line — so it lands in shell history, in ps output on a shared box, and
// in the journal — and then sent on every heartbeat for the life of the node.
// It never expired, and there was no way to rotate or revoke it short of
// deleting the node and enrolling it again. Anyone who ever saw that string
// could be that node indefinitely, and nothing on the panel could tell.
//
// Now: a short-lived, single-use bootstrap token buys ONE client certificate,
// and that certificate authenticates everything afterwards. Its private key is
// generated on the node and never leaves it, so nothing authenticating is ever
// in flight to intercept. It expires on its own, it renews before it does, and
// revoking it is a panel-side action that does not need the node's cooperation
// — which matters, because a node whose key has leaked is exactly the node that
// will not help you.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/nodeca"
	"github.com/forgepanel/forgepanel/internal/store"
)

// BootstrapTTL is how long an enrolment command stays usable.
//
// Short on purpose. The command is pasted into terminals, chat and ticket
// systems; the window in which it is worth anything should be the window in
// which someone is actually running it.
const BootstrapTTL = 30 * time.Minute

// nodeCA returns the panel's node CA, creating it on first use.
//
// Held on the Server, NOT in a package-level sync.Once. A package singleton
// would make every Server in one process share one CA rooted at whichever data
// directory happened to be opened first — wrong for any process that runs two
// panels, and silently wrong in tests, where it would have made each case
// inherit the previous case's fleet.
func (s *Server) nodeCA() (*nodeca.CA, error) {
	s.nodeCAOnce.Do(func() {
		s.nodeCARef, s.nodeCAErr = nodeca.Open(filepath.Join(s.cfg.DataDir, "nodeca"))
	})
	return s.nodeCARef, s.nodeCAErr
}

// hashBootstrap is the at-rest form of a bootstrap token.
func hashBootstrap(tok string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return hex.EncodeToString(sum[:])
}

// requireNodeMTLS reports whether legacy token authentication is still allowed.
func (s *Server) requireNodeMTLS() bool {
	p := s.cfg.Panel()
	return p != nil && p.RequireNodeMTLS
}

// nodeFromClientCert identifies the node behind a request's client certificate.
//
// Returns ok=false when no certificate was presented at all, which is not an
// error — it is how a legacy agent, and every browser, reaches these routes.
func (s *Server) nodeFromClientCert(c *gin.Context) (uint, bool, error) {
	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		return 0, false, nil
	}
	ca, err := s.nodeCA()
	if err != nil {
		return 0, false, err
	}
	id, err := ca.VerifyNode(c.Request.TLS.PeerCertificates[0])
	if err != nil {
		return 0, true, err
	}
	return id, true, nil
}

// authenticateNode resolves the node behind a node-facing request.
//
// mTLS first, then the legacy token. The order matters: a node that has a
// certificate must be judged on it, so that revoking the certificate actually
// stops it even while its old token row still exists.
func (s *Server) authenticateNode(c *gin.Context, token string) (*store.Node, error) {
	id, presented, err := s.nodeFromClientCert(c)
	if err != nil {
		return nil, err
	}
	if presented {
		n, err := s.db.NodeByID(id)
		if err != nil {
			return nil, fmt.Errorf("the certificate names node %d, which no longer exists", id)
		}
		return n, nil
	}
	if s.requireNodeMTLS() {
		return nil, errors.New("this panel requires a node client certificate; " +
			"re-run the enrolment command on the node to obtain one")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("no client certificate and no token")
	}
	n, err := s.db.NodeByToken(token)
	if err != nil {
		return nil, errors.New("invalid enroll token")
	}
	return n, nil
}

// bootstrapRequest is a node exchanging its one-time token for a certificate.
type bootstrapRequest struct {
	Token string `json:"token"`
	// CSRPEM is the node's certificate request. The node generates the key and
	// keeps it: no private key is ever transmitted, which is the property that
	// makes this stronger than any bearer token.
	CSRPEM string `json:"csr_pem"`
}

// handleNodeBootstrap exchanges a one-time bootstrap token for a client
// certificate. Node-facing, unauthenticated except by the token itself.
func (s *Server) handleNodeBootstrap(c *gin.Context) {
	var req bootstrapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Token) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		fail(c, http.StatusBadRequest, "token and csr_pem are both required")
		return
	}
	n, err := s.db.NodeByBootstrapHash(hashBootstrap(req.Token))
	if err != nil {
		// One message for "no such token" and "expired": distinguishing them
		// turns this into an oracle for which tokens ever existed.
		fail(c, http.StatusUnauthorized, "the bootstrap token is not valid or has expired")
		return
	}
	if n.BootstrapExpires == nil || time.Now().After(*n.BootstrapExpires) {
		fail(c, http.StatusUnauthorized, "the bootstrap token is not valid or has expired")
		return
	}

	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		fail(c, http.StatusBadRequest, "csr_pem is not PEM")
		return
	}
	ca, err := s.nodeCA()
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "node-cert-sign", Kind: apierr.KindServer,
			Message: "the node CA is unavailable", Cause: err,
			Details: map[string]any{"detail": err.Error()}})
		return
	}
	issued, err := ca.SignNodeCSR(block.Bytes, n.ID)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "node-cert-sign", Kind: apierr.KindValidation,
			Message: "the certificate request was refused", Cause: err,
			Details: map[string]any{"detail": err.Error()}})
		return
	}

	// Spend the token. Single-use is the whole point: an enrolment command that
	// still works after the node has enrolled is a permanent credential again,
	// just with extra steps.
	n.BootstrapHash = ""
	n.BootstrapExpires = nil
	n.CertSerial = issued.Serial
	n.CertNotAfter = &issued.NotAfter
	n.Enrolled = true
	if err := s.db.SaveNode(n); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"node_id":    n.ID,
		"name":       n.Name,
		"cert_pem":   string(issued.CertPEM),
		"ca_pem":     string(issued.CAPEM),
		"not_after":  issued.NotAfter,
		"renew_from": issued.RenewFrom,
	})
}

// handleNodeRenew issues a fresh certificate to a node that already holds a
// valid one. Authenticated by the current certificate, not by any token.
func (s *Server) handleNodeRenew(c *gin.Context) {
	id, presented, err := s.nodeFromClientCert(c)
	if !presented || err != nil {
		detail := "no client certificate was presented"
		if err != nil {
			detail = err.Error()
		}
		apierr.Fail(c, &apierr.Error{Op: "node-cert-renew", Kind: apierr.KindAuth,
			Message: "renewal requires the node's current client certificate",
			Details: map[string]any{"detail": detail}})
		return
	}
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.CSRPEM) == "" {
		fail(c, http.StatusBadRequest, "csr_pem is required")
		return
	}
	n, err := s.db.NodeByID(id)
	if err != nil {
		fail(c, http.StatusUnauthorized, "this certificate names a node that no longer exists")
		return
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		fail(c, http.StatusBadRequest, "csr_pem is not PEM")
		return
	}
	ca, _ := s.nodeCA()
	issued, err := ca.SignNodeCSR(block.Bytes, n.ID)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "node-cert-sign", Kind: apierr.KindValidation,
			Message: "the certificate request was refused", Cause: err,
			Details: map[string]any{"detail": err.Error()}})
		return
	}
	// Revoke the certificate being replaced. Leaving it valid until it expires
	// would mean a renewal after a suspected compromise achieves nothing for
	// another thirty days.
	if old := strings.TrimSpace(n.CertSerial); old != "" && old != issued.Serial {
		_ = ca.Revoke(old)
	}
	n.CertSerial = issued.Serial
	n.CertNotAfter = &issued.NotAfter
	_ = s.db.SaveNode(n)

	c.JSON(http.StatusOK, gin.H{
		"cert_pem":   string(issued.CertPEM),
		"ca_pem":     string(issued.CAPEM),
		"not_after":  issued.NotAfter,
		"renew_from": issued.RenewFrom,
	})
}

// revokeNodeCert is called when a node is deleted, so its certificate stops
// working immediately rather than at expiry.
func (s *Server) revokeNodeCert(n *store.Node) {
	if n == nil || strings.TrimSpace(n.CertSerial) == "" {
		return
	}
	if ca, err := s.nodeCA(); err == nil {
		_ = ca.Revoke(n.CertSerial)
	}
}

// nodeClientCAPool is the pool the panel's TLS listener verifies node
// certificates against.
func (s *Server) nodeClientCAPool() *x509.CertPool {
	ca, err := s.nodeCA()
	if err != nil {
		return nil
	}
	return ca.Pool()
}
