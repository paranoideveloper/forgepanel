package wgpeer

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// plainSealer stands in for the panel's encryptor. The sealing is not what these
// tests are about, and a real one would need key material set up per test.
type plainSealer struct{}

func (plainSealer) Encrypt(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
func (plainSealer) Decrypt(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

// testManager uses the REAL store, on purpose: the behaviour under test is what
// happens when SQLite's unique index rejects a second insert, and a fake repo
// would not have one.
func testManager(t *testing.T) *Manager {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db, plainSealer{})
}

// Two callers ensuring the same peer at once must both get the same peer.
//
// EnsurePeer reads, then inserts, and those are not one transaction — so two
// callers can both find nothing and both insert, and the unique index turns the
// loser into an error. This is not hypothetical: applyWGPeers runs while a
// config is rendered, reloadEngines is started in the background from many
// handlers, and two overlapping reloads race for exactly this row. It showed up
// as an intermittent
//
//	UNIQUE constraint failed: wg_peers.inbound_id, wg_peers.user_id
//
// in a loaded test suite. In production the loser is dropped from the rendered
// peer list, disconnecting a client because something else happened to be
// creating its peer at the same moment.
func TestConcurrentEnsurePeerAgreesOnOnePeer(t *testing.T) {
	m := testManager(t)

	const callers = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		peers []*Peer
		errs  []error
	)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // released together, to make the window as wide as it gets
			p, err := m.EnsurePeer(1, 1, "10.66.66.1/24")
			mu.Lock()
			if err != nil {
				errs = append(errs, err)
			} else {
				peers = append(peers, p)
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d of %d callers failed; the first: %v", len(errs), callers, errs[0])
	}
	if len(peers) != callers {
		t.Fatalf("got %d peers back, want %d", len(peers), callers)
	}
	// Every caller must see the SAME peer: a second keypair for one user is a
	// client that authenticates against a key the server does not list.
	for _, p := range peers[1:] {
		if p.PublicKey != peers[0].PublicKey {
			t.Fatalf("callers disagree on the peer: %q vs %q", p.PublicKey, peers[0].PublicKey)
		}
		if p.Address != peers[0].Address {
			t.Fatalf("callers disagree on the address: %q vs %q", p.Address, peers[0].Address)
		}
	}

	// And exactly one row exists, so the peer list the server renders has one
	// entry for this user rather than several.
	rows, err := m.repo.PeersForInbound(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d peer rows for one (inbound, user), want 1", len(rows))
	}
}

// The ordinary path still works, so the race handling has not turned a real
// failure into a silent success.
func TestEnsurePeerIsIdempotentWhenCalledTwice(t *testing.T) {
	m := testManager(t)
	first, err := m.EnsurePeer(2, 3, "10.66.66.1/24")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.EnsurePeer(2, 3, "10.66.66.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey != second.PublicKey || first.Address != second.Address {
		t.Fatal("a second EnsurePeer minted a different peer")
	}
}

// A genuine failure must still be reported: if the insert fails for a reason
// that is NOT a lost race, the recovery read finds nothing and the error stands.
func TestAGenuineCreateFailureIsStillReported(t *testing.T) {
	m := testManager(t)
	// An address pool that cannot allocate is the cheapest real failure.
	if _, err := m.EnsurePeer(4, 5, "not-a-cidr"); err == nil {
		t.Fatal("an unusable server CIDR was accepted")
	}
}
