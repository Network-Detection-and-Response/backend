package ml_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/google/uuid"
)

func sampleFlow(id uuid.UUID) domain.Flow {
	srcMAC := "00:1A:2B:3C:4D:5E"
	return domain.Flow{
		ID: id, SensorID: "s1", ObservedAt: time.Now().UTC(),
		SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &srcMAC,
		DstIP:   netip.MustParseAddr("10.0.0.5"),
		SrcPort: 54321, DstPort: 443, Protocol: "TCP",
		DurationMs: 1500, TotalPackets: 45, TotalBytes: 35000,
		TCPFlags: domain.TCPFlags{SYN: 1, ACK: 40, RST: 0},
	}
}

func TestPredictSuccess(t *testing.T) {
	flowID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/predict" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("content-type=%q", ct)
		}
		var req ml.PredictRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(req.Flows) != 1 || req.Flows[0].FlowID != flowID.String() {
			t.Fatalf("unexpected request: %+v", req)
		}
		if req.Flows[0].SrcMAC == nil || *req.Flows[0].SrcMAC != "00:1A:2B:3C:4D:5E" {
			t.Fatalf("src_mac=%v", req.Flows[0].SrcMAC)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []map[string]any{{
				"flow_id": flowID.String(),
				"probabilities": map[string]float64{
					"Normal": 0.20, "PortScan": 0.60, "DDoS": 0.10, "BruteForce": 0.10,
				},
			}},
		})
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, 2*time.Second)
	preds, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(flowID)})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("len=%d", len(preds))
	}
	if preds[0].Probabilities["PortScan"] != 0.60 {
		t.Fatalf("PortScan=%v", preds[0].Probabilities["PortScan"])
	}
}

func TestPredictNotConfigured(t *testing.T) {
	client := ml.NewClient("", time.Second)
	_, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(uuid.New())})
	if err != ml.ErrNotConfigured {
		t.Fatalf("err=%v want ErrNotConfigured", err)
	}
}

func TestPredictRejectsInvalidProbabilities(t *testing.T) {
	flowID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []map[string]any{{
				"flow_id": flowID.String(),
				"probabilities": map[string]float64{
					"Normal": 0.9, "PortScan": 0.9, "DDoS": 0.9, "BruteForce": 0.9,
				},
			}},
		})
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, time.Second)
	_, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(flowID)})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPredictHTTPErrorDoesNotFabricate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, time.Second)
	preds, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(uuid.New())})
	if err == nil {
		t.Fatal("expected error")
	}
	if preds != nil {
		t.Fatalf("must not fabricate predictions, got %+v", preds)
	}
}

func TestPredictTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, 50*time.Millisecond)
	_, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(uuid.New())})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestValidateProbabilities(t *testing.T) {
	if err := ml.ValidateProbabilities(map[string]float64{
		"Normal": 0.25, "PortScan": 0.25, "DDoS": 0.25, "BruteForce": 0.25,
	}); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := ml.ValidateProbabilities(map[string]float64{
		"Normal": 0.5, "PortScan": 0.5,
	}); err == nil {
		t.Fatal("missing classes should fail")
	}
	if err := ml.ValidateProbabilities(map[string]float64{
		"Normal": 0.49, "PortScan": 0.49, "DDoS": 0.01, "BruteForce": 0.01,
	}); err != nil {
		t.Fatalf("sum within tolerance should pass: %v", err)
	}
}

func TestPredictInvalidJSONDoesNotFabricate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, time.Second)
	preds, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(uuid.New())})
	if err == nil {
		t.Fatal("expected error")
	}
	if preds != nil {
		t.Fatalf("must not fabricate: %+v", preds)
	}
}

func TestPredictRejectsUnknownFlowID(t *testing.T) {
	flowID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []map[string]any{{
				"flow_id": uuid.New().String(),
				"probabilities": map[string]float64{
					"Normal": 0.25, "PortScan": 0.25, "DDoS": 0.25, "BruteForce": 0.25,
				},
			}},
		})
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, time.Second)
	preds, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(flowID)})
	if err == nil {
		t.Fatal("expected error for unexpected flow_id")
	}
	if preds != nil {
		t.Fatalf("must not fabricate: %+v", preds)
	}
}

func TestPredictNaNProbabilitiesRejected(t *testing.T) {
	flowID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"predictions":[{"flow_id":"` + flowID.String() + `","probabilities":{"Normal":"NaN","PortScan":0.25,"DDoS":0.25,"BruteForce":0.25}}]}`))
	}))
	defer srv.Close()

	client := ml.NewClient(srv.URL, time.Second)
	_, err := client.Predict(context.Background(), []domain.Flow{sampleFlow(flowID)})
	if err == nil {
		t.Fatal("expected error")
	}
}
