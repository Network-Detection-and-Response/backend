package agent

import (
	"strings"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

// MatchWhitelist returns true when an enabled schedule exactly matches the flow
// for every non-null schedule field and the observed UTC time falls in the window.
//
// Matching rules (UTC):
//   - null schedule fields are wildcards;
//   - non-null src_ip / src_mac / dst_ip / protocol must equal the flow values;
//   - days_of_week uses Go weekday numbering (0=Sunday … 6=Saturday);
//   - start_time/end_time compare clock-of-day; if start > end the window crosses midnight.
//
// No rule is inferred when schedules are empty.
func MatchWhitelist(flow domain.Flow, observedAt time.Time, schedules []domain.WhitelistSchedule) (bool, string) {
	obs := observedAt.UTC()
	for _, s := range schedules {
		if !s.Enabled {
			continue
		}
		if !fieldsMatch(flow, s) {
			continue
		}
		if !dayAllowed(obs.Weekday(), s.DaysOfWeek) {
			continue
		}
		if !clockInWindow(obs, s.StartTime, s.EndTime) {
			continue
		}
		return true, s.Name
	}
	return false, ""
}

func fieldsMatch(flow domain.Flow, s domain.WhitelistSchedule) bool {
	if s.SrcIP != nil && *s.SrcIP != flow.SrcIP {
		return false
	}
	if s.DstIP != nil && *s.DstIP != flow.DstIP {
		return false
	}
	if s.Protocol != nil && !strings.EqualFold(strings.TrimSpace(*s.Protocol), flow.Protocol) {
		return false
	}
	if s.SrcMAC != nil {
		if flow.SrcMAC == nil {
			return false
		}
		if !macEqual(*s.SrcMAC, *flow.SrcMAC) {
			return false
		}
	}
	return true
}

func macEqual(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "-", ":"), strings.ReplaceAll(b, "-", ":"))
}

func dayAllowed(day time.Weekday, days []int16) bool {
	if len(days) == 0 {
		return true
	}
	d := int16(day)
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

func clockInWindow(obs, start, end time.Time) bool {
	o := secondsOfDay(obs)
	s := secondsOfDay(start)
	e := secondsOfDay(end)
	if s == e {
		// Zero-length window: treat as full day only when both are midnight?
		// Spec: exact window; empty span matches nothing.
		return false
	}
	if s < e {
		return o >= s && o < e
	}
	// Overnight: e.g. 22:00–06:00
	return o >= s || o < e
}

func secondsOfDay(t time.Time) int {
	u := t.UTC()
	return u.Hour()*3600 + u.Minute()*60 + u.Second()
}
