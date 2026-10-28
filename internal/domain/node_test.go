package domain

import (
	"net/netip"
	"testing"
)

func TestMakeNodeIDPrefersMAC(t *testing.T) {
	mac := "00-1a-2b-3c-4d-5e"
	ip := netip.MustParseAddr("192.168.1.50")
	got := MakeNodeID(&mac, ip)
	want := "mac:00:1A:2B:3C:4D:5E"
	if got != want {
		t.Fatalf("MakeNodeID = %q, want %q", got, want)
	}
}

func TestMakeNodeIDFallsBackToIP(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	got := MakeNodeID(nil, ip)
	want := "ip:10.0.0.5"
	if got != want {
		t.Fatalf("MakeNodeID = %q, want %q", got, want)
	}
}

func TestNormalizeMACInvalid(t *testing.T) {
	if _, ok := NormalizeMAC("not-a-mac"); ok {
		t.Fatal("expected invalid MAC")
	}
}
