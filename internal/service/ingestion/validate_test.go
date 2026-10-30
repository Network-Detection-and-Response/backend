package ingestion

import (
	"strings"
	"testing"
)

func validBatchJSON() string {
	return `{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [
    {
      "src_ip": "192.168.1.50",
      "src_mac": "00:1A:2B:3C:4D:5E",
      "dst_ip": "10.0.0.5",
      "dst_mac": "AA:BB:CC:DD:EE:FF",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "duration_ms": 1500,
      "total_packets": 45,
      "total_bytes": 35000,
      "tcp_flags": { "syn": 1, "ack": 40, "rst": 0 }
    }
  ]
}`
}

func TestDecodeAndValidateAcceptsValidBatch(t *testing.T) {
	job, err := DecodeAndValidate([]byte(validBatchJSON()), 500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if job.SensorID != "core_switch_mirror" {
		t.Fatalf("sensor_id = %q", job.SensorID)
	}
	if len(job.Flows) != 1 {
		t.Fatalf("flows = %d", len(job.Flows))
	}
	if job.Flows[0].SrcMAC == nil || *job.Flows[0].SrcMAC != "00:1A:2B:3C:4D:5E" {
		t.Fatalf("src_mac = %v", job.Flows[0].SrcMAC)
	}
	if job.BatchID.String() == "" {
		t.Fatal("batch id empty")
	}
}

func TestDecodeAndValidateNullMAC(t *testing.T) {
	body := `{
  "sensor_id": "s1",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [{
    "src_ip": "192.168.1.50",
    "src_mac": null,
    "dst_ip": "10.0.0.5",
    "dst_mac": null,
    "src_port": 1234,
    "dst_port": 80,
    "protocol": "TCP",
    "duration_ms": 1,
    "total_packets": 1,
    "total_bytes": 100
  }]
}`
	job, err := DecodeAndValidate([]byte(body), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if job.Flows[0].SrcMAC != nil || job.Flows[0].DstMAC != nil {
		t.Fatalf("expected null MACs, got src=%v dst=%v", job.Flows[0].SrcMAC, job.Flows[0].DstMAC)
	}
}

func TestDecodeAndValidateRejectsEmptyFlows(t *testing.T) {
	body := `{"sensor_id":"s1","timestamp":"2026-10-09T14:30:00Z","flows":[]}`
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "empty")
}

func TestDecodeAndValidateRejectsInvalidIP(t *testing.T) {
	body := strings.Replace(validBatchJSON(), "192.168.1.50", "not-an-ip", 1)
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "src_ip")
}

func TestDecodeAndValidateRejectsInvalidMAC(t *testing.T) {
	body := strings.Replace(validBatchJSON(), "00:1A:2B:3C:4D:5E", "bad-mac", 1)
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "src_mac")
}

func TestDecodeAndValidateRejectsInvalidPort(t *testing.T) {
	body := strings.Replace(validBatchJSON(), `"src_port": 54321`, `"src_port": 0`, 1)
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "src_port")
}

func TestDecodeAndValidateRejectsNegativeCounters(t *testing.T) {
	body := strings.Replace(validBatchJSON(), `"total_bytes": 35000`, `"total_bytes": -1`, 1)
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "total_bytes")
}

func TestDecodeAndValidateRejectsInvalidTimestamp(t *testing.T) {
	body := strings.Replace(validBatchJSON(), "2026-10-09T14:30:00Z", "yesterday", 1)
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "timestamp")
}

func TestDecodeAndValidateRejectsTooManyFlows(t *testing.T) {
	if _, err := DecodeAndValidate([]byte(validBatchJSON()), 1); err != nil {
		t.Fatalf("limit 1 should accept 1 flow: %v", err)
	}
	two := `{
  "sensor_id":"s1","timestamp":"2026-10-09T14:30:00Z","flows":[
    {"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","src_port":1,"dst_port":2,"protocol":"UDP","duration_ms":0,"total_packets":1,"total_bytes":1},
    {"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","src_port":3,"dst_port":4,"protocol":"UDP","duration_ms":0,"total_packets":1,"total_bytes":1}
  ]}`
	_, err := DecodeAndValidate([]byte(two), 1)
	assertValidation(t, err, "PAYLOAD_TOO_LARGE", "limit")
}

func TestDecodeAndValidateRejectsUnknownFields(t *testing.T) {
	body := `{"sensor_id":"s1","timestamp":"2026-10-09T14:30:00Z","extra":true,"flows":[{"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","src_port":1,"dst_port":2,"protocol":"UDP","duration_ms":0,"total_packets":1,"total_bytes":1}]}`
	_, err := DecodeAndValidate([]byte(body), 10)
	assertValidation(t, err, "VALIDATION_ERROR", "unknown")
}

func assertValidation(t *testing.T, err error, code, msgPart string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("want *ValidationError, got %T (%v)", err, err)
	}
	if ve.Code != code {
		t.Fatalf("code = %q, want %q", ve.Code, code)
	}
	if msgPart != "" && !strings.Contains(strings.ToLower(ve.Message), strings.ToLower(msgPart)) {
		t.Fatalf("message %q should contain %q", ve.Message, msgPart)
	}
}
