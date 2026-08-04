package api

import (
	"sync"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// NodeStore is a minimal thread-safe in-memory store of nodes keyed by a
// subscription token. The core build uses it for the subscription endpoint; the
// full build (spec §4) replaces it with the GORM-backed repositories while
// keeping this interface shape.
type NodeStore struct {
	mu    sync.RWMutex
	byTok map[string][]*model.Node
}

// NewNodeStore returns an empty store seeded with a demo token so the
// subscription endpoint is exercisable immediately after boot.
func NewNodeStore() *NodeStore {
	return &NodeStore{byTok: map[string][]*model.Node{}}
}

// Set replaces the node list for a token.
func (s *NodeStore) Set(token string, nodes []*model.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTok[token] = nodes
}

// Get returns the nodes for a token (nil if unknown).
func (s *NodeStore) Get(token string) []*model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTok[token]
}
