package domain

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// TCPFlags holds observed TCP flag counters from a flow.
type TCPFlags struct {
	SYN int64
	ACK int64
	RST int64
}

// Flow is a stored network session metadata record.
type Flow struct {
	ID           uuid.UUID
	BatchID      uuid.UUID
	SensorID     string
	ObservedAt   time.Time
	SrcIP        netip.Addr
	SrcMAC       *string
	DstIP        netip.Addr
	DstMAC       *string
	SrcPort      int
	DstPort      int
	Protocol     string
	DurationMs   int64
	TotalPackets int64
	TotalBytes   int64
	TCPFlags     TCPFlags
	CreatedAt    time.Time
}
