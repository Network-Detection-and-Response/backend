package incidents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotFound   = errors.New("incident not found")
	ErrValidation = errors.New("validation error")
	ErrConflict   = errors.New("status transition conflict")
)

// Store is the persistence surface for incident queries.
type Store interface {
	ListIncidents(ctx context.Context, f postgres.IncidentListFilter) ([]domain.Incident, int64, error)
	GetIncidentByID(ctx context.Context, id uuid.UUID) (domain.Incident, error)
	UpdateIncidentStatus(ctx context.Context, id uuid.UUID, status string) (domain.Incident, error)
}

// Service implements incident read/update use cases.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

// ListQuery is a validated list request.
type ListQuery struct {
	Page     int
	PageSize int
	Severity string
	Status   string
	Since    string
	Until    string
}

// ListResult is a paginated page.
type ListResult struct {
	Items    []domain.Incident
	Page     int
	PageSize int
	Total    int64
}

func (s *Service) List(ctx context.Context, q ListQuery) (ListResult, error) {
	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100 // API_CONTRACTS: cap page_size at 100
	}

	f := postgres.IncidentListFilter{Page: page, PageSize: pageSize}
	if q.Severity != "" {
		if _, ok := domain.ValidSeverities[q.Severity]; !ok {
			return ListResult{}, fmt.Errorf("%w: invalid severity", ErrValidation)
		}
		sev := q.Severity
		f.Severity = &sev
	}
	if q.Status != "" {
		if _, ok := domain.ValidStatuses[q.Status]; !ok {
			return ListResult{}, fmt.Errorf("%w: invalid status", ErrValidation)
		}
		st := q.Status
		f.Status = &st
	}
	if q.Since != "" {
		t, err := time.Parse(time.RFC3339, q.Since)
		if err != nil {
			return ListResult{}, fmt.Errorf("%w: since must be RFC3339", ErrValidation)
		}
		t = t.UTC()
		f.Since = &t
	}
	if q.Until != "" {
		t, err := time.Parse(time.RFC3339, q.Until)
		if err != nil {
			return ListResult{}, fmt.Errorf("%w: until must be RFC3339", ErrValidation)
		}
		t = t.UTC()
		f.Until = &t
	}
	if f.Since != nil && f.Until != nil && f.Until.Before(*f.Since) {
		return ListResult{}, fmt.Errorf("%w: until must be >= since", ErrValidation)
	}

	items, total, err := s.store.ListIncidents(ctx, f)
	if err != nil {
		return ListResult{}, err
	}
	return ListResult{Items: items, Page: page, PageSize: pageSize, Total: total}, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (domain.Incident, error) {
	inc, err := s.store.GetIncidentByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, ErrNotFound
	}
	return inc, err
}

func (s *Service) PatchStatus(ctx context.Context, id uuid.UUID, newStatus string) (domain.Incident, error) {
	inc, err := s.store.GetIncidentByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, ErrNotFound
	}
	if err != nil {
		return domain.Incident{}, err
	}
	if err := domain.CanTransitionStatus(inc.Status, newStatus); err != nil {
		if _, ok := domain.PatchableStatuses[newStatus]; !ok {
			return domain.Incident{}, fmt.Errorf("%w: %s", ErrValidation, err.Error())
		}
		return domain.Incident{}, fmt.Errorf("%w: %s", ErrConflict, err.Error())
	}
	updated, err := s.store.UpdateIncidentStatus(ctx, id, newStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, ErrNotFound
	}
	return updated, err
}
