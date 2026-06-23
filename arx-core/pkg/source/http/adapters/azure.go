// ====== Module: Azure Monitor Data Collector Adapter ======
// Implements Azure Monitor Data Collector API format.
// Expects JSON array of records with "time" field (RFC3339).

package adapters

import (
	"encoding/json"
	"fmt"

	nethttp "net/http"
)

// init registers the azure factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("azure", func(cfg AdapterConfig) (Adapter, error) {
		return &AzureAdapter{}, nil
	})
}

// AzureAdapter implements Adapter for Azure Monitor Data Collector API.
// Expects JSON array payload: [{"time":"RFC3339","msg":"..."}, ...]
// Called from: buildPushHandler() during HTTP request processing.
type AzureAdapter struct{}

// Decode parses Azure JSON array, extracts RFC3339 timestamps from "time" field.
// Returns raw JSON and timestamp for each record.
// Called from: buildPushHandler() to process Azure webhook payloads.
func (a *AzureAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var rawMsgs []json.RawMessage
	if err := json.Unmarshal(body, &rawMsgs); err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	records := make([]EnvelopeRecord, 0, len(rawMsgs))
	for _, raw := range rawMsgs {
		var ts int64
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			if timeRaw, ok := obj["time"]; ok {
				var timeStr string
				if err := json.Unmarshal(timeRaw, &timeStr); err == nil {
					ts, _ = normalizeTimestamp(timeStr, "rfc3339")
				}
			}
		}
		records = append(records, EnvelopeRecord{RawLine: string(raw), Timestamp: ts})
	}
	return records, nil
}

// WriteAck writes 204 No Content response — Azure expects empty success acknowledgment.
// Non-blocking. Called from: buildPushHandler() after successful Decode().
func (a *AzureAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
