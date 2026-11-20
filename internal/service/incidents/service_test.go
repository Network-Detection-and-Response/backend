package incidents_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/incidents"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type memStore struct {
	items map[uuid.UUID]domain.Incident
}

func newMemStore(incs ...domain.Incident) *memStore {
	m := &memStore{items: map[uuid.UUID]domain.Incident{}}
	for _, inc := range incs {
		m.items[inc.ID] = inc
	}
	return m
}

func (m *memStore) ListIncidents(ctx context.Context, f postgres.IncidentListFilter) ([]domain.Incident, int64, error) {
	var out []domain.Incident
	for _, inc := range m.items {
		if f.Severity != nil && inc.Severity != *f.Severity {
			continue
		}
		if f.Status != nil && inc.Status != *f.Status {
			continue
		}
		out = append(out, inc)
	}
	return out, int64(len(out)), nil
}

func (m *memStore) GetIncidentByID(ctx context.Context, id uuid.UUID) (domain.Incident, error) {
	inc, ok := m.items[id]
	if !ok {
		return domain.Incident{}, pgx.ErrNoRows
	}
	return inc, nil
}

func (m *memStore) UpdateIncidentStatus(ctx context.Context, id uuid.UUID, status string) (domain.Incident, error) {
	inc, ok := m.items[id]
	if !ok {
		return domain.Incident{}, pgx.ErrNoRows
	}
	inc.Status = status
	m.items[id] = inc
	return inc, nil
}

func sampleIncident(status, severity string) domain.Incident {
	return domain.Incident{
		ID: uuid.New(), CreatedAt: time.Now().UTC(),
		SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
		AttackClass: domain.AttackPortScan, Severity: severity, Status: status,
		MLConfidence: 0.7, AgentVerdict: "v", RecommendedAction: "a",
	}
}

func TestListCapsHugePageSize(t *testing.T) {
	svc := incidents.NewService(newMemStore())
	res, err := svc.List(context.Background(), incidents.ListQuery{Page: 1, PageSize: 101})
	if err != nil {
		t.Fatal(err)
	}
	if res.PageSize != 100 {
		t.Fatalf("page_size=%d want 100", res.PageSize)
	}
}

func TestPatchStatusTransition(t *testing.T) {
	inc := sampleIncident(domain.StatusOpen, domain.SeverityHigh)
	svc := incidents.NewService(newMemStore(inc))
	updated, err := svc.PatchStatus(context.Background(), inc.ID, domain.StatusAcknowledged)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != domain.StatusAcknowledged {
		t.Fatalf("status=%s", updated.Status)
	}
	_, err = svc.PatchStatus(context.Background(), inc.ID, domain.StatusOpen)
	if err == nil {
		t.Fatal("OPEN patch must fail")
	}
}
