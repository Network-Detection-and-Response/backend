package domain

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Severity levels for incidents.
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Incident status values.
const (
	StatusOpen          = "OPEN"
	StatusAcknowledged  = "ACKNOWLEDGED"
	StatusResolved      = "RESOLVED"
	StatusFalsePositive = "FALSE_POSITIVE"
)

// Attack class labels from ML / decision agent.
const (
	AttackNormal     = "Normal"
	AttackPortScan   = "PortScan"
	AttackDDoS       = "DDoS"
	AttackBruteForce = "BruteForce"
	AttackUnknown    = "Unknown"
)

// Incident is a stored security verdict linked to an optional flow.
type Incident struct {
	ID                uuid.UUID
	FlowID            *uuid.UUID
	CreatedAt         time.Time
	SrcIP             netip.Addr
	SrcMAC            *string
	DstIP             netip.Addr
	DstMAC            *string
	AttackClass       string
	Severity          string
	Status            string
	MLConfidence      float64
	AgentVerdict      string
	RecommendedAction string
	ContextSummary    json.RawMessage
}

// WhitelistSchedule is an exact-match maintenance/false-positive window.
// Times and days_of_week are interpreted in UTC by the backend.
type WhitelistSchedule struct {
	ID         uuid.UUID
	Name       string
	SrcIP      *netip.Addr
	SrcMAC     *string
	DstIP      *netip.Addr
	Protocol   *string
	StartTime  time.Time // date component ignored; use clock in UTC
	EndTime    time.Time
	DaysOfWeek []int16
	Enabled    bool
	CreatedAt  time.Time
}
