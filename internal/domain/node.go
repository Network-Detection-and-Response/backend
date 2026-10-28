package domain

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Node is an observed network endpoint.
type Node struct {
	ID            string
	MACAddress    *string
	IPAddress     netip.Addr
	DeviceType    string
	FirstSeen     time.Time
	LastSeen      time.Time
	IsCompromised bool
	UpdatedAt     time.Time
}

// Edge is an observed communication between two nodes for a protocol.
type Edge struct {
	ID           uuid.UUID
	SourceNodeID string
	TargetNodeID string
	Protocol     string
	TotalBytes   int64
	TotalPackets int64
	LastSeen     time.Time
	UpdatedAt    time.Time
}

// MakeNodeID builds a stable node identifier.
// Prefer MAC when present: mac:AA:BB:CC:DD:EE:FF; otherwise ip:<address>.
func MakeNodeID(mac *string, ip netip.Addr) string {
	if mac != nil {
		if normalized, ok := NormalizeMAC(*mac); ok {
			return "mac:" + normalized
		}
	}
	return "ip:" + ip.String()
}

// NormalizeMAC accepts common MAC forms and returns canonical AA:BB:CC:DD:EE:FF.
func NormalizeMAC(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ToUpper(s)

	// Support 12 hex digits without separators.
	if !strings.Contains(s, ":") && len(s) == 12 {
		parts := make([]string, 0, 6)
		for i := 0; i < 12; i += 2 {
			parts = append(parts, s[i:i+2])
		}
		s = strings.Join(parts, ":")
	}

	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return "", false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return "", false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				return "", false
			}
		}
	}
	return strings.Join(parts, ":"), true
}

// ParseNodeID validates a stored node id prefix.
func ParseNodeID(id string) error {
	if strings.HasPrefix(id, "mac:") || strings.HasPrefix(id, "ip:") {
		if len(id) <= 3 {
			return fmt.Errorf("node id too short")
		}
		return nil
	}
	return fmt.Errorf("node id must start with mac: or ip:")
}
