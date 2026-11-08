package agent

import (
	"fmt"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

// Explainer produces Russian-language text. It must not change structured fields.
type Explainer interface {
	Explain(v Verdict, flow domain.Flow) (verdictText, recommendedAction string, err error)
}

// TemplateExplainer builds deterministic Russian explanations (no network).
type TemplateExplainer struct{}

func (TemplateExplainer) Explain(v Verdict, flow domain.Flow) (string, string, error) {
	text, action := TemplateExplainer{}.mustExplain(v, flow)
	return text, action, nil
}

func (TemplateExplainer) mustExplain(v Verdict, flow domain.Flow) (string, string) {
	src := flow.SrcIP.String()
	dst := flow.DstIP.String()
	conf := formatConfidence(v.Confidence)

	var text string
	switch v.AttackClass {
	case domain.AttackPortScan:
		text = fmt.Sprintf(
			"Обнаружена подозрительная сетевая активность класса PortScan (уверенность %.2f) от %s к %s.",
			v.Confidence, src, dst,
		)
	case domain.AttackDDoS:
		text = fmt.Sprintf(
			"Обнаружена подозрительная сетевая активность класса DDoS (уверенность %.2f) от %s к %s.",
			v.Confidence, src, dst,
		)
	case domain.AttackBruteForce:
		text = fmt.Sprintf(
			"Обнаружена подозрительная сетевая активность класса BruteForce (уверенность %.2f) от %s к %s.",
			v.Confidence, src, dst,
		)
	default:
		text = fmt.Sprintf(
			"Обнаружена подозрительная сетевая активность класса %s (уверенность %s) от %s к %s.",
			v.AttackClass, conf, src, dst,
		)
	}

	if v.WhitelistMatched {
		name := v.WhitelistName
		if name == "" {
			name = "whitelist"
		}
		text += fmt.Sprintf(
			" Совпадение с разрешённым расписанием «%s»: severity снижена, статус FALSE_POSITIVE.",
			name,
		)
	}

	action := "Рекомендуется проверить источник и назначение трафика; подтвердите инцидент перед ограничением доступа."
	return text, action
}

// OptionalLLMExplainer tries an LLM for wording only; structured fields stay unchanged.
// On any failure it falls back to TemplateExplainer.
type OptionalLLMExplainer struct {
	Inner   LLMClient
	Enabled bool
}

// LLMClient is the optional network surface for rewriting explanation text.
type LLMClient interface {
	RewriteExplanation(v Verdict, flow domain.Flow, templateVerdict, templateAction string) (verdictText, recommendedAction string, err error)
}

func (e OptionalLLMExplainer) Explain(v Verdict, flow domain.Flow) (string, string, error) {
	baseText, baseAction := TemplateExplainer{}.mustExplain(v, flow)
	if !e.Enabled || e.Inner == nil {
		return baseText, baseAction, nil
	}
	text, action, err := e.Inner.RewriteExplanation(v, flow, baseText, baseAction)
	if err != nil || text == "" || action == "" {
		return baseText, baseAction, nil
	}
	return text, action, nil
}
