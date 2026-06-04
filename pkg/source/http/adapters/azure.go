package adapters

import (
	"encoding/json"
	"fmt"

	nethttp "net/http"
)

type AzureAdapter struct{}

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

func (a *AzureAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
