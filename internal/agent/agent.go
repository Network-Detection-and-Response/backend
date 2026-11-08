package agent

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/google/uuid"
)

// Attack classes considered for incident creation (excludes Normal).
var attackClasses = []string{
	domain.AttackPortScan,
	domain.AttackDDoS,
	domain.AttackBruteForce,
}

// Config controls decision thresholds.
type Config struct {
	AttackThreshold       float64 // default 0.60
	DDoSCriticalThreshold float64 // default 0.85
}

// Context is optional historical / whitelist input for EvaluateFlow.
type Context struct {
	ObservedAt          time.Time
	Schedules           []domain.WhitelistSchedule
	RecentSrcFlowCount  int64 // simple aggregate; 0 means unavailable / unused
	RecentSrcFlowWindow time.Duration
}

// Verdict is a structured incident candidate. Class/confidence/severity are
// never taken from an LLM.
type Verdict struct {
	FlowID            uuid.UUID
	AttackClass       string
	Confidence        float64
	Severity          string
	Status            string
	AgentVerdict      string
	RecommendedAction string
	ContextSummary    json.RawMessage
	WhitelistMatched  bool
	WhitelistName     string
}

// Agent applies deterministic rules from BACKEND_SPEC.md.
type Agent struct {
	cfg       Config
	explainer Explainer
}

// New creates a Decision Agent. explainer may be nil (templates only).
func New(cfg Config, explainer Explainer) *Agent {
	if cfg.AttackThreshold <= 0 || cfg.AttackThreshold > 1 {
		cfg.AttackThreshold = 0.60
	}
	if cfg.DDoSCriticalThreshold <= 0 || cfg.DDoSCriticalThreshold > 1 {
		cfg.DDoSCriticalThreshold = 0.85
	}
	if explainer == nil {
		explainer = TemplateExplainer{}
	}
	return &Agent{cfg: cfg, explainer: explainer}
}

// EvaluateFlow returns an optional incident verdict.
// No incident when Normal is the top class or the strongest attack
// probability is below AttackThreshold. Invalid probabilities return an error
// and must not create an incident.
func (a *Agent) EvaluateFlow(flow domain.Flow, probabilities map[string]float64, ctx Context) (*Verdict, error) {
	if err := ml.ValidateProbabilities(probabilities); err != nil {
		return nil, err
	}

	topClass, topProb := argMax(probabilities)
	attackClass, attackProb := topAttack(probabilities)

	if topClass == domain.AttackNormal || attackProb < a.cfg.AttackThreshold {
		return nil, nil
	}

	severity := severityFor(attackClass, attackProb, a.cfg)
	status := domain.StatusOpen

	observed := ctx.ObservedAt
	if observed.IsZero() {
		observed = flow.ObservedAt
	}
	matched, scheduleName := MatchWhitelist(flow, observed, ctx.Schedules)
	if matched {
		status = domain.StatusFalsePositive
		severity = downgradeSeverity(severity)
	}

	summary := buildContextSummary(topClass, topProb, attackClass, attackProb, matched, scheduleName, ctx)
	v := &Verdict{
		FlowID:           flow.ID,
		AttackClass:      attackClass,
		Confidence:       attackProb,
		Severity:         severity,
		Status:           status,
		ContextSummary:   summary,
		WhitelistMatched: matched,
		WhitelistName:    scheduleName,
	}

	text, action, err := a.explainer.Explain(*v, flow)
	if err != nil {
		text, action = TemplateExplainer{}.mustExplain(*v, flow)
	}
	v.AgentVerdict = text
	v.RecommendedAction = action
	return v, nil
}

// ToIncident maps a verdict onto a domain.Incident ready for persistence.
func (v Verdict) ToIncident(flow domain.Flow) domain.Incident {
	fid := flow.ID
	return domain.Incident{
		ID:                uuid.New(),
		FlowID:            &fid,
		CreatedAt:         time.Now().UTC(),
		SrcIP:             flow.SrcIP,
		SrcMAC:            flow.SrcMAC,
		DstIP:             flow.DstIP,
		DstMAC:            flow.DstMAC,
		AttackClass:       v.AttackClass,
		Severity:          v.Severity,
		Status:            v.Status,
		MLConfidence:      v.Confidence,
		AgentVerdict:      v.AgentVerdict,
		RecommendedAction: v.RecommendedAction,
		ContextSummary:    v.ContextSummary,
	}
}

func severityFor(class string, confidence float64, cfg Config) string {
	switch class {
	case domain.AttackDDoS:
		if confidence >= cfg.DDoSCriticalThreshold {
			return domain.SeverityCritical
		}
		return domain.SeverityHigh
	case domain.AttackPortScan, domain.AttackBruteForce:
		return domain.SeverityMedium
	default:
		return domain.SeverityMedium
	}
}

func downgradeSeverity(s string) string {
	switch s {
	case domain.SeverityCritical:
		return domain.SeverityHigh
	case domain.SeverityHigh:
		return domain.SeverityMedium
	case domain.SeverityMedium:
		return domain.SeverityLow
	default:
		return domain.SeverityLow
	}
}

func argMax(p map[string]float64) (string, float64) {
	bestClass := domain.AttackUnknown
	best := math.Inf(-1)
	for _, class := range ml.RequiredClasses {
		if p[class] > best {
			best = p[class]
			bestClass = class
		}
	}
	return bestClass, best
}

func topAttack(p map[string]float64) (string, float64) {
	bestClass := domain.AttackUnknown
	best := math.Inf(-1)
	for _, class := range attackClasses {
		if p[class] > best {
			best = p[class]
			bestClass = class
		}
	}
	return bestClass, best
}

func buildContextSummary(
	topClass string, topProb float64,
	attackClass string, attackProb float64,
	matched bool, scheduleName string,
	ctx Context,
) json.RawMessage {
	m := map[string]any{
		"top_class":          topClass,
		"top_probability":    topProb,
		"attack_class":       attackClass,
		"attack_probability": attackProb,
		"whitelist_matched":  matched,
	}
	if matched {
		m["whitelist_name"] = scheduleName
	}
	if ctx.RecentSrcFlowCount > 0 {
		m["recent_src_flow_count"] = ctx.RecentSrcFlowCount
		if ctx.RecentSrcFlowWindow > 0 {
			m["recent_src_flow_window"] = ctx.RecentSrcFlowWindow.String()
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func formatConfidence(v float64) string {
	return fmt.Sprintf("%.2f", v)
}
