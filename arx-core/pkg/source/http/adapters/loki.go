// ====== Module: Grafana Loki Adapter ======
// Implements Grafana Loki push API format.
// Expects JSON with streams array, each containing labels and values.

package adapters

import (
	"encoding/json"
	"fmt"
	"strconv"

	nethttp "net/http"
)

// init registers the loki factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("loki", func(cfg AdapterConfig) (Adapter, error) {
		return &LokiAdapter{}, nil
	})
}

// LokiAdapter implements Adapter for Grafana Loki push API.
// Expects JSON: {"streams":[{"stream":{"label":"val"},"values":[["ts","line"]]}]}
// Called from: buildPushHandler() during HTTP request processing.
type LokiAdapter struct{}

// lokiPushRequest represents Grafana Loki push API request format.
type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

// lokiStream represents a Loki stream with labels and log entries.
type lokiStream struct {
	Stream map[string]string `json:"stream"` // YAML: Loki labels (job, instance, etc.)
	Values [][]string        `json:"values"` // YAML: [[timestamp, line], ...]
}

// Decode parses Loki push JSON, extracts timestamps and lines from values.
// Populates Metadata with stream labels for downstream processing.
// Called from: buildPushHandler() to process Loki push payloads.
func (a *LokiAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var req lokiPushRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("loki: %w", err)
	}
	var records []EnvelopeRecord
	for _, s := range req.Streams {
		for _, val := range s.Values {
			if len(val) < 2 {
				continue
			}
			ts, _ := strconv.ParseInt(val[0], 10, 64) // per-record best-effort; 0 if unparseable
			records = append(records, EnvelopeRecord{
				RawLine:   val[1],
				Timestamp: ts,
				Metadata:  copyMap(s.Stream),
			})
		}
	}
	return records, nil
}

// WriteAck writes 204 No Content response. Non-blocking.
func (a *LokiAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
