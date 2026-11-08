package agent_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/agent"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
)

func sampleFlow() domain.Flow {
	srcMAC := "00:1A:2B:3C:4D:5E"
	return domain.Flow{
		ID: uuid.New(), ObservedAt: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC),
		SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &srcMAC,
		DstIP:    netip.MustParseAddr("10.0.0.5"),
		Protocol: "TCP", SrcPort: 1, DstPort: 80,
	}
}

func probs(n, ps, dd, bf float64) map[string]float64 {
	return map[string]float64{
		domain.AttackNormal: n, domain.AttackPortScan: ps,
		domain.AttackDDoS: dd, domain.AttackBruteForce: bf,
	}
}

func TestNormalHighestNoIncident(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.70, 0.10, 0.10, 0.10), agent.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatalf("expected no incident, got %+v", v)
	}
}

func TestAttackBelowThresholdNoIncident(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.45, 0.55, 0.00, 0.00), agent.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatalf("expected no incident below threshold, got %+v", v)
	}
}

func TestPortScanAboveThresholdMedium(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.20, 0.60, 0.10, 0.10), agent.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		t.Fatal("expected incident")
	}
	if v.AttackClass != domain.AttackPortScan || v.Severity != domain.SeverityMedium || v.Status != domain.StatusOpen {
		t.Fatalf("got %+v", v)
	}
	if v.AgentVerdict == "" || v.RecommendedAction == "" {
		t.Fatal("missing Russian explanation/action")
	}
}

func TestBruteForceMedium(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.10, 0.10, 0.10, 0.70), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Severity != domain.SeverityMedium || v.AttackClass != domain.AttackBruteForce {
		t.Fatalf("got %+v", v)
	}
}

func TestDDoSCriticalAtThreshold(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.05, 0.05, 0.85, 0.05), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Severity != domain.SeverityCritical {
		t.Fatalf("severity=%s want CRITICAL", v.Severity)
	}
}

func TestDDoSHighBelowCritical(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.10, 0.10, 0.70, 0.10), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Severity != domain.SeverityHigh {
		t.Fatalf("severity=%s want HIGH", v.Severity)
	}
}

func TestInvalidProbabilitiesRejected(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60}, nil)
	_, err := a.EvaluateFlow(sampleFlow(), map[string]float64{"Normal": 2}, agent.Context{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWhitelistMatchMarksFalsePositiveAndDowngrades(t *testing.T) {
	flow := sampleFlow()
	src := flow.SrcIP
	start := time.Date(2000, 1, 1, 14, 0, 0, 0, time.UTC)
	end := time.Date(2000, 1, 1, 15, 0, 0, 0, time.UTC)
	sched := []domain.WhitelistSchedule{{
		ID: uuid.New(), Name: "backup-window", SrcIP: &src,
		StartTime: start, EndTime: end,
		DaysOfWeek: []int16{0, 1, 2, 3, 4, 5, 6}, Enabled: true,
	}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(flow, probs(0.05, 0.05, 0.85, 0.05), agent.Context{
		ObservedAt: flow.ObservedAt, Schedules: sched,
	})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Status != domain.StatusFalsePositive {
		t.Fatalf("status=%s", v.Status)
	}
	if v.Severity != domain.SeverityHigh { // CRITICAL -> HIGH
		t.Fatalf("severity=%s want HIGH after downgrade", v.Severity)
	}
	// Original ML class/confidence must be preserved under FALSE_POSITIVE.
	if v.AttackClass != domain.AttackDDoS || v.Confidence != 0.85 {
		t.Fatalf("must keep ML class/confidence: class=%s conf=%v", v.AttackClass, v.Confidence)
	}
	if !v.WhitelistMatched || v.WhitelistName != "backup-window" {
		t.Fatalf("whitelist meta %+v", v)
	}
}

func TestAttackThresholdBoundaries(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	// Exactly at threshold → incident (rule uses attackProb < threshold).
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.40, 0.60, 0.00, 0.00), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("at threshold want incident: v=%v err=%v", v, err)
	}
	// Just below threshold → no incident.
	v, err = a.EvaluateFlow(sampleFlow(), probs(0.41, 0.59, 0.00, 0.00), agent.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatalf("below threshold must skip, got %+v", v)
	}
}

func TestWhitelistOutsideUTCWindowDoesNotMatch(t *testing.T) {
	flow := sampleFlow() // 14:30 UTC
	src := flow.SrcIP
	start := time.Date(2000, 1, 1, 10, 0, 0, 0, time.UTC)
	end := time.Date(2000, 1, 1, 11, 0, 0, 0, time.UTC)
	sched := []domain.WhitelistSchedule{{
		ID: uuid.New(), Name: "morning", SrcIP: &src,
		StartTime: start, EndTime: end,
		DaysOfWeek: []int16{0, 1, 2, 3, 4, 5, 6}, Enabled: true,
	}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(flow, probs(0.20, 0.60, 0.10, 0.10), agent.Context{
		ObservedAt: flow.ObservedAt, Schedules: sched,
	})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Status != domain.StatusOpen || v.WhitelistMatched {
		t.Fatalf("outside window must not match: %+v", v)
	}
}

func TestWhitelistOvernightUTCWindow(t *testing.T) {
	flow := sampleFlow()
	flow.ObservedAt = time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC)
	src := flow.SrcIP
	start := time.Date(2000, 1, 1, 22, 0, 0, 0, time.UTC)
	end := time.Date(2000, 1, 1, 6, 0, 0, 0, time.UTC)
	sched := []domain.WhitelistSchedule{{
		ID: uuid.New(), Name: "night", SrcIP: &src,
		StartTime: start, EndTime: end,
		DaysOfWeek: []int16{0, 1, 2, 3, 4, 5, 6}, Enabled: true,
	}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(flow, probs(0.20, 0.60, 0.10, 0.10), agent.Context{
		ObservedAt: flow.ObservedAt, Schedules: sched,
	})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Status != domain.StatusFalsePositive || !v.WhitelistMatched {
		t.Fatalf("overnight window should match: %+v", v)
	}
}

func TestNoScheduleMatchDoesNotSuppress(t *testing.T) {
	flow := sampleFlow()
	other := netip.MustParseAddr("10.9.9.9")
	start := time.Date(2000, 1, 1, 14, 0, 0, 0, time.UTC)
	end := time.Date(2000, 1, 1, 15, 0, 0, 0, time.UTC)
	sched := []domain.WhitelistSchedule{{
		ID: uuid.New(), Name: "other", SrcIP: &other,
		StartTime: start, EndTime: end,
		DaysOfWeek: []int16{0, 1, 2, 3, 4, 5, 6}, Enabled: true,
	}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	v, err := a.EvaluateFlow(flow, probs(0.20, 0.60, 0.10, 0.10), agent.Context{
		ObservedAt: flow.ObservedAt, Schedules: sched,
	})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.Status != domain.StatusOpen || v.WhitelistMatched {
		t.Fatalf("must not suppress: %+v", v)
	}
}

type failingLLM struct{}

func (failingLLM) RewriteExplanation(v agent.Verdict, flow domain.Flow, templateVerdict, templateAction string) (string, string, error) {
	return "", "", errors.New("llm down")
}

type rewritingLLM struct{}

func (rewritingLLM) RewriteExplanation(v agent.Verdict, flow domain.Flow, templateVerdict, templateAction string) (string, string, error) {
	// Returns only text; agent must ignore any attempt to influence structured fields.
	return "Переписанный текст LLM.", "Переписанная рекомендация LLM.", nil
}

func TestLLMUnavailableUsesTemplate(t *testing.T) {
	explainer := agent.OptionalLLMExplainer{Enabled: true, Inner: failingLLM{}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, explainer)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.20, 0.60, 0.10, 0.10), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.AgentVerdict == "" || v.RecommendedAction == "" {
		t.Fatal("template fallback missing text")
	}
	if v.AttackClass != domain.AttackPortScan || v.Severity != domain.SeverityMedium {
		t.Fatalf("LLM must not change structured fields: %+v", v)
	}
}

func TestLLMSuccessChangesOnlyText(t *testing.T) {
	explainer := agent.OptionalLLMExplainer{Enabled: true, Inner: rewritingLLM{}}
	a := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, explainer)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.10, 0.10, 0.70, 0.10), agent.Context{})
	if err != nil || v == nil {
		t.Fatalf("v=%v err=%v", v, err)
	}
	if v.AttackClass != domain.AttackDDoS || v.Confidence != 0.70 || v.Severity != domain.SeverityHigh {
		t.Fatalf("LLM must not change class/confidence/severity: %+v", v)
	}
	if v.AgentVerdict != "Переписанный текст LLM." {
		t.Fatalf("verdict text=%q", v.AgentVerdict)
	}
}

func TestRecommendationIsAdvisory(t *testing.T) {
	a := agent.New(agent.Config{AttackThreshold: 0.60}, nil)
	v, err := a.EvaluateFlow(sampleFlow(), probs(0.20, 0.60, 0.10, 0.10), agent.Context{})
	if err != nil || v == nil {
		t.Fatal(err)
	}
	if containsBlockClaim(v.RecommendedAction) {
		t.Fatalf("must not claim IP was blocked: %s", v.RecommendedAction)
	}
}

func containsBlockClaim(s string) bool {
	lower := strings.ToLower(s)
	for _, bad := range []string{"заблокирован", "blocked automatically", "ip blocked"} {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}
