package domain_test

import (
	"testing"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

func TestCanTransitionStatus(t *testing.T) {
	cases := []struct {
		from, to string
		ok       bool
	}{
		{domain.StatusOpen, domain.StatusAcknowledged, true},
		{domain.StatusOpen, domain.StatusResolved, true},
		{domain.StatusOpen, domain.StatusFalsePositive, true},
		{domain.StatusOpen, domain.StatusOpen, false},
		{domain.StatusAcknowledged, domain.StatusResolved, true},
		{domain.StatusAcknowledged, domain.StatusFalsePositive, true},
		{domain.StatusAcknowledged, domain.StatusOpen, false},
		{domain.StatusResolved, domain.StatusAcknowledged, false},
		{domain.StatusFalsePositive, domain.StatusResolved, false},
	}
	for _, tc := range cases {
		err := domain.CanTransitionStatus(tc.from, tc.to)
		if tc.ok && err != nil {
			t.Fatalf("%s -> %s: unexpected err %v", tc.from, tc.to, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s -> %s: expected error", tc.from, tc.to)
		}
	}
}

func TestShouldNotifyTelegram(t *testing.T) {
	if !domain.ShouldNotifyTelegram(domain.SeverityCritical, domain.StatusOpen) {
		t.Fatal("CRITICAL OPEN should notify")
	}
	if !domain.ShouldNotifyTelegram(domain.SeverityHigh, domain.StatusOpen) {
		t.Fatal("HIGH OPEN should notify")
	}
	if domain.ShouldNotifyTelegram(domain.SeverityMedium, domain.StatusOpen) {
		t.Fatal("MEDIUM must not notify")
	}
	if domain.ShouldNotifyTelegram(domain.SeverityHigh, domain.StatusFalsePositive) {
		t.Fatal("FALSE_POSITIVE must not notify")
	}
}
