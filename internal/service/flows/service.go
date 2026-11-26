package flows

import (
	"context"
	"fmt"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
)

var ErrValidation = fmt.Errorf("validation error")

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Store loads recent flow rows for the dashboard list.
type Store interface {
	ListRecentFlows(ctx context.Context, limit, offset int) ([]postgres.FlowListItem, int64, error)
}

// ListQuery is GET /api/v1/flows pagination.
type ListQuery struct {
	Limit  int
	Offset int
}

// ListItem is the API-facing recent-flow row.
type ListItem struct {
	ID           string `json:"id"`
	SensorID     string `json:"sensor_id"`
	ObservedAt   string `json:"observed_at"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      int    `json:"src_port"`
	DstPort      int    `json:"dst_port"`
	Protocol     string `json:"protocol"`
	TotalPackets int64  `json:"total_packets"`
	TotalBytes   int64  `json:"total_bytes"`
}

// ListResult is the paginated response model.
type ListResult struct {
	Items      []ListItem
	Total      int64
	Limit      int
	Offset     int
}

// Service lists recent network flows.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

// List returns recent flows sorted by observed_at DESC.
func (s *Service) List(ctx context.Context, q ListQuery) (ListResult, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return ListResult{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrValidation, MaxLimit)
	}
	if q.Offset < 0 {
		return ListResult{}, fmt.Errorf("%w: offset must be >= 0", ErrValidation)
	}

	rows, total, err := s.store.ListRecentFlows(ctx, limit, q.Offset)
	if err != nil {
		return ListResult{}, err
	}

	items := make([]ListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, ListItem{
			ID:           row.ID.String(),
			SensorID:     row.SensorID,
			ObservedAt:   row.ObservedAt.UTC().Format(time.RFC3339),
			SrcIP:        row.SrcIP.String(),
			DstIP:        row.DstIP.String(),
			SrcPort:      row.SrcPort,
			DstPort:      row.DstPort,
			Protocol:     row.Protocol,
			TotalPackets: row.TotalPackets,
			TotalBytes:   row.TotalBytes,
		})
	}
	return ListResult{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: q.Offset,
	}, nil
}
