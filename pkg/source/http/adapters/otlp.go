package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	nethttp "net/http"
)

type OTLPAdapter struct{}

type otlpRequest struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type resourceLogs struct {
	ScopeLogs []scopeLogs `json:"scopeLogs"`
}

type scopeLogs struct {
	LogRecords []logRecord `json:"logRecords"`
}

type logRecord struct {
	TimeUnixNano string     `json:"timeUnixNano"`
	Body         otlpBody   `json:"body"`
	Attributes   []otlpAttr `json:"attributes"`
}

type otlpBody struct {
	StringValue string `json:"stringValue"`
	BytesValue  string `json:"bytesValue"`
}

type otlpAttr struct {
	Key   string      `json:"key"`
	Value otlpAttrVal `json:"value"`
}

type otlpAttrVal struct {
	StringValue string `json:"stringValue"`
}

func (a *OTLPAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var req otlpRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("otlp: %w", err)
	}
	var records []EnvelopeRecord
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				rawLine := lr.Body.StringValue
				if rawLine == "" && lr.Body.BytesValue != "" {
					decoded, err := base64.StdEncoding.DecodeString(lr.Body.BytesValue)
					if err != nil {
						rawLine = lr.Body.BytesValue
					} else {
						rawLine = string(decoded)
					}
				}

				ts, _ := normalizeTimestamp(lr.TimeUnixNano, "unix_ns_str") // per-record best-effort; 0 if unparseable

				meta := make(map[string]string)
				for _, attr := range lr.Attributes {
					meta[attr.Key] = attr.Value.StringValue
				}

				records = append(records, EnvelopeRecord{
					RawLine:   rawLine,
					Timestamp: ts,
					Metadata:  meta,
				})
			}
		}
	}
	return records, nil
}

func (a *OTLPAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, `{"partialSuccess":{}}`)
}
