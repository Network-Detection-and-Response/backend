package flows

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
)

type stubStore struct {
	items []postgres.FlowListItem
	total int64
	err   error
}

func (s stubStore) ListRecentFlows(ctx context.Context, limit, offset int) ([]postgres.FlowListItem, int64, error) {
	_ = ctx
	_ = limit
	_ = offset
	return s.items, s.total, s.err
}

func TestListDefaultsAndBounds(t *testing.T) {
	svc := NewService(stubStore{})

	if _, err := svc.List(context.Background(), ListQuery{Limit: 0, Offset: 0}); err != nil {
		t.Fatalf("default limit: %v", err)
	}
	if _, err := svc.List(context.Background(), ListQuery{Limit: 201, Offset: 0}); err == nil {
		t.Fatal("expected limit>200 validation error")
	}
	if _, err := svc.List(context.Background(), ListQuery{Limit: 50, Offset: -1}); err == nil {
		t.Fatal("expected offset<0 validation error")
	}
}

func TestListMapsRows(t *testing.T) {
	id := uuid.New()
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	svc := NewService(stubStore{
		total: 1,
		items: []postgres.FlowListItem{{
			ID:           id,
			SensorID:     "core_switch_mirror",
			ObservedAt:   at,
			SrcIP:        netip.MustParseAddr("10.0.0.1"),
			DstIP:        netip.MustParseAddr("10.0.0.2"),
			SrcPort:      443,
			DstPort:      52341,
			Protocol:     "TCP",
			TotalPackets: 12,
			TotalBytes:   1500,
		}},
	})

	res, err := svc.List(context.Background(), ListQuery{Limit: 50, Offset: 0})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if res.Total != 1 || res.Limit != 50 || len(res.Items) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	item := res.Items[0]
	if item.ID != id.String() || item.SrcIP != "10.0.0.1" || item.Protocol != "TCP" {
		t.Fatalf("unexpected item: %+v", item)
	}
	if item.ObservedAt != "2026-11-26T12:00:00Z" {
		t.Fatalf("observed_at: %s", item.ObservedAt)
	}
}
