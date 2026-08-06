package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

var (
	ErrNodeNotFound     = errors.New("service: node not found")
	ErrInboundNotFound  = errors.New("service: inbound not found")
	ErrUserNotFound     = errors.New("service: user not found")
	ErrInvalidMigration = errors.New("service: invalid migration target")
)

type Manager struct {
	db store.Interface
}

func NewManager(db store.Interface) *Manager {
	return &Manager{db: db}
}

// --- NodeService implementation ---

func (m *Manager) EnrollNode(ctx context.Context, name, address string) (*store.Node, string, string, error) {
	if name == "" {
		return nil, "", "", errors.New("service: node name is required")
	}
	tok, err := keygen.Password(24)
	if err != nil {
		return nil, "", "", fmt.Errorf("service: mint enroll token: %w", err)
	}
	n := &store.Node{Name: name, Address: address, EnrollToken: tok}
	if err := m.db.CreateNode(n); err != nil {
		return nil, "", "", fmt.Errorf("service: create node: %w", err)
	}
	enrollCmd := fmt.Sprintf("TOKEN=%s bash -c 'node-install.sh'", tok)
	return n, enrollCmd, tok, nil
}

func (m *Manager) ListNodes(ctx context.Context) ([]store.Node, error) {
	return m.db.ListNodes()
}

func (m *Manager) GetNode(ctx context.Context, id uint) (*store.Node, error) {
	nodes, err := m.db.ListNodes()
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if n.ID == id {
			return &n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (m *Manager) DecommissionNode(ctx context.Context, nodeID uint, fallbackNodeID uint) error {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	inbounds, _ := m.db.ListInbounds()
	attachedCount := 0
	for _, in := range inbounds {
		n, err := in.Node()
		if err == nil && n.Address == node.Address {
			attachedCount++
		}
	}
	if attachedCount > 0 && fallbackNodeID == 0 {
		return fmt.Errorf("%w: node has %d attached inbounds; specify a fallback node", ErrInvalidMigration, attachedCount)
	}
	if fallbackNodeID != 0 && fallbackNodeID == nodeID {
		return fmt.Errorf("%w: fallback node cannot be the deleted node", ErrInvalidMigration)
	}
	if fallbackNodeID != 0 {
		if _, err := m.GetNode(ctx, fallbackNodeID); err != nil {
			return fmt.Errorf("service: fallback node invalid: %w", err)
		}
		if _, err := m.MigrateNodeInbounds(ctx, nodeID, fallbackNodeID); err != nil {
			return fmt.Errorf("service: failed to migrate inbounds: %w", err)
		}
	}
	return m.db.DeleteNode(node.ID)
}

// --- InboundService implementation ---

func (m *Manager) CreateInbound(ctx context.Context, n *model.Node) (*store.Inbound, error) {
	if n == nil {
		return nil, errors.New("service: nil node spec")
	}
	n.Normalize()
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("service: invalid node spec: %w", err)
	}
	return m.db.CreateInbound(n)
}

func (m *Manager) UpdateInbound(ctx context.Context, id uint, n *model.Node) (*store.Inbound, error) {
	in, err := m.db.InboundByID(id)
	if err != nil {
		return nil, fmt.Errorf("service: inbound %d: %w", id, err)
	}
	n.Normalize()
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("service: invalid node spec: %w", err)
	}
	if err := in.SetNode(n); err != nil {
		return nil, err
	}
	if err := m.db.SaveInbound(in); err != nil {
		return nil, err
	}
	return in, nil
}

func (m *Manager) DeleteInbound(ctx context.Context, id uint, fallbackInboundID uint) error {
	if _, err := m.db.InboundByID(id); err != nil {
		return ErrInboundNotFound
	}
	if fallbackInboundID != 0 {
		if _, err := m.db.InboundByID(fallbackInboundID); err != nil {
			return fmt.Errorf("%w: fallback inbound %d not found", ErrInboundNotFound, fallbackInboundID)
		}
		users, err := m.db.ListUsers(0)
		if err == nil {
			for _, u := range users {
				assigns, aerr := m.db.UserAssignments(u.ID)
				if aerr != nil {
					continue
				}
				newDirect := make([]uint, 0, len(assigns.Direct))
				hasTarget := false
				for _, inID := range assigns.Direct {
					if inID == id {
						hasTarget = true
					} else {
						newDirect = append(newDirect, inID)
					}
				}
				if hasTarget {
					newDirect = append(newDirect, fallbackInboundID)
					_ = m.db.SetUserInbounds(u.ID, newDirect, nil)
				}
			}
		}
	}
	return m.db.DeleteInbound(id)
}

func (m *Manager) ListInbounds(ctx context.Context) ([]store.Inbound, error) {
	return m.db.ListInbounds()
}

// --- TrafficService implementation ---

func (m *Manager) RecordTraffic(ctx context.Context, username string, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	users, err := m.db.ListUsers(0)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Username == username {
			if 9223372036854775807-bytes < u.UsedTraffic {
				u.UsedTraffic = 9223372036854775807
			} else {
				u.UsedTraffic += bytes
			}
			return m.db.SaveUser(&u)
		}
	}
	return ErrUserNotFound
}

func (m *Manager) PollAndSyncTraffic(ctx context.Context, stats map[string]int64) ([]uint, error) {
	var expired []uint
	now := time.Now()
	for username, delta := range stats {
		if delta <= 0 {
			continue
		}
		users, err := m.db.ListUsers(0)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if u.Username == username {
				if 9223372036854775807-delta < u.UsedTraffic {
					u.UsedTraffic = 9223372036854775807
				} else {
					u.UsedTraffic += delta
				}
				if u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit {
					u.Status = store.StatusDisabled
					expired = append(expired, u.ID)
				} else if u.ExpireAt != nil && now.After(*u.ExpireAt) {
					u.Status = store.StatusExpired
					expired = append(expired, u.ID)
				}
				_ = m.db.SaveUser(&u)
				break
			}
		}
	}
	return expired, nil
}

func (m *Manager) ResetUserTraffic(ctx context.Context, userID uint) error {
	u, err := m.db.UserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	u.UsedTraffic = 0
	if u.Status == store.StatusDisabled {
		u.Status = store.StatusActive
	}
	return m.db.SaveUser(u)
}

// --- UserMigrationService implementation ---

func (m *Manager) MigrateUser(ctx context.Context, userID uint, targetGroupID uint, targetInboundIDs []uint) error {
	u, err := m.db.UserByID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	if targetGroupID != 0 {
		if _, err := m.db.GroupByID(targetGroupID); err != nil {
			return fmt.Errorf("service: target group %d invalid: %w", targetGroupID, err)
		}
		u.GroupID = targetGroupID
		if err := m.db.SaveUser(u); err != nil {
			return err
		}
	}
	if targetInboundIDs != nil {
		if err := m.db.SetUserInbounds(userID, targetInboundIDs, nil); err != nil {
			return fmt.Errorf("service: set direct inbounds: %w", err)
		}
	}
	return nil
}

func (m *Manager) MigrateNodeInbounds(ctx context.Context, sourceNodeID uint, destinationNodeID uint) (int, error) {
	if sourceNodeID == destinationNodeID {
		return 0, fmt.Errorf("%w: source and destination nodes are identical", ErrInvalidMigration)
	}
	inbounds, err := m.db.ListInbounds()
	if err != nil {
		return 0, err
	}
	destNode, err := m.GetNode(ctx, destinationNodeID)
	if err != nil {
		return 0, fmt.Errorf("service: destination node %d invalid: %w", destinationNodeID, err)
	}
	migrated := 0
	for _, in := range inbounds {
		n, err := in.Node()
		if err != nil {
			continue
		}
		sourceNode, serr := m.GetNode(ctx, sourceNodeID)
		if serr != nil {
			return 0, fmt.Errorf("service: source node %d invalid: %w", sourceNodeID, serr)
		}
		if n.Address == sourceNode.Address && destNode.Address != "" {
			n.Address = destNode.Address
			if err := in.SetNode(n); err == nil {
				if err := m.db.SaveInbound(&in); err == nil {
					migrated++
				}
			}
		}
	}
	return migrated, nil
}

// ValidateNodeAddress checks node IP / hostname against SSRF & dangerous loopback targets.
func ValidateNodeAddress(addr string) error {
	if addr == "" {
		return nil
	}
	if addr == "127.0.0.1" || addr == "localhost" || addr == "::1" || addr == "0.0.0.0" {
		return errors.New("service: node address cannot be loopback or wildcard")
	}
	return nil
}

// MergeNodeClientTraffic calculates the exact incremental delta for a node user
// based on NodeClientTraffic cumulative baseline, preventing double counting on restarts.
func (m *Manager) MergeNodeClientTraffic(ctx context.Context, nodeID uint, username string, cumulativeBytes int64) (int64, error) {
	if cumulativeBytes < 0 {
		return 0, nil
	}

	nt, err := m.db.GetNodeClientTraffic(nodeID, username)
	if err != nil {
		// New baseline entry for this (node, user)
		newNT := &store.NodeClientTraffic{NodeID: nodeID, Username: username, LastRecorded: cumulativeBytes}
		_ = m.db.SaveNodeClientTraffic(newNT)
		if cumulativeBytes > 0 {
			_ = m.RecordTraffic(ctx, username, cumulativeBytes)
		}
		return cumulativeBytes, nil
	}

	var delta int64
	if cumulativeBytes < nt.LastRecorded {
		// Node restarted or counter reset -> delta is current cumulative
		delta = cumulativeBytes
	} else {
		delta = cumulativeBytes - nt.LastRecorded
	}

	nt.LastRecorded = cumulativeBytes
	_ = m.db.SaveNodeClientTraffic(nt)

	if delta > 0 {
		_ = m.RecordTraffic(ctx, username, delta)
	}

	return delta, nil
}

// SanitizeInboundSpec strips master-internal fields before handing config specs to node agents.
func SanitizeInboundSpec(spec *model.Node) *model.Node {
	if spec == nil {
		return nil
	}
	cl := spec.Clone()
	cl.Normalize()
	return cl
}

// MarkNodeDirty marks a node as needing configuration re-sync.
func (m *Manager) MarkNodeDirty(ctx context.Context, nodeID uint) error {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	now := time.Now()
	node.ConfigDirty = true
	node.ConfigDirtyAt = &now
	return m.db.SaveNode(node)
}

// ClearNodeDirty clears dirty flag after a successful network sync.
func (m *Manager) ClearNodeDirty(ctx context.Context, nodeID uint) error {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	node.ConfigDirty = false
	node.ConfigDirtyAt = nil
	return m.db.SaveNode(node)
}
