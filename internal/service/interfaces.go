package service

import (
	"context"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// NodeService manages remote proxy nodes and migration.
type NodeService interface {
	EnrollNode(ctx context.Context, name, address string) (node *store.Node, command string, token string, err error)
	ListNodes(ctx context.Context) ([]store.Node, error)
	GetNode(ctx context.Context, id uint) (*store.Node, error)
	DecommissionNode(ctx context.Context, nodeID uint, fallbackNodeID uint) error
}

// InboundService manages inbound configurations and lifecycle.
type InboundService interface {
	CreateInbound(ctx context.Context, n *model.Node) (*store.Inbound, error)
	UpdateInbound(ctx context.Context, id uint, n *model.Node) (*store.Inbound, error)
	DeleteInbound(ctx context.Context, id uint, fallbackInboundID uint) error
	ListInbounds(ctx context.Context) ([]store.Inbound, error)
}

// TrafficService manages user traffic accounting, quotas, and resets.
type TrafficService interface {
	RecordTraffic(ctx context.Context, email string, bytes int64) error
	PollAndSyncTraffic(ctx context.Context, stats map[string]int64) (expiredUsers []uint, err error)
	ResetUserTraffic(ctx context.Context, userID uint) error
}

// UserMigrationService manages complex user/node/inbound migration workflows.
type UserMigrationService interface {
	MigrateUser(ctx context.Context, userID uint, targetGroupID uint, targetInboundIDs []uint) error
	MigrateNodeInbounds(ctx context.Context, sourceNodeID uint, destinationNodeID uint) (migratedCount int, err error)
}
