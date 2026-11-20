package domain

import "fmt"

// PatchableStatuses are values allowed in PATCH /api/v1/incidents/{id}.
var PatchableStatuses = map[string]struct{}{
	StatusAcknowledged:  {},
	StatusResolved:      {},
	StatusFalsePositive: {},
}

// ValidSeverities for list filters.
var ValidSeverities = map[string]struct{}{
	SeverityLow:      {},
	SeverityMedium:   {},
	SeverityHigh:     {},
	SeverityCritical: {},
}

// ValidStatuses for list filters.
var ValidStatuses = map[string]struct{}{
	StatusOpen:          {},
	StatusAcknowledged:  {},
	StatusResolved:      {},
	StatusFalsePositive: {},
}

// CanTransitionStatus reports whether from -> to is allowed.
//
// Rules:
//   - OPEN -> ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE
//   - ACKNOWLEDGED -> RESOLVED | FALSE_POSITIVE
//   - RESOLVED and FALSE_POSITIVE are terminal
//   - PATCH cannot set OPEN
func CanTransitionStatus(from, to string) error {
	if _, ok := PatchableStatuses[to]; !ok {
		return fmt.Errorf("status %q is not allowed in PATCH; use ACKNOWLEDGED, RESOLVED or FALSE_POSITIVE", to)
	}
	if from == to {
		return fmt.Errorf("incident already has status %s", to)
	}
	switch from {
	case StatusOpen:
		return nil
	case StatusAcknowledged:
		if to == StatusResolved || to == StatusFalsePositive {
			return nil
		}
		return fmt.Errorf("cannot transition from %s to %s", from, to)
	case StatusResolved, StatusFalsePositive:
		return fmt.Errorf("status %s is terminal", from)
	default:
		return fmt.Errorf("unknown current status %q", from)
	}
}

// ShouldNotifyTelegram reports whether a newly created incident should be enqueued.
// Only HIGH/CRITICAL; FALSE_POSITIVE (whitelist) is skipped even if severity remains HIGH.
func ShouldNotifyTelegram(severity, status string) bool {
	if status == StatusFalsePositive {
		return false
	}
	return severity == SeverityHigh || severity == SeverityCritical
}
