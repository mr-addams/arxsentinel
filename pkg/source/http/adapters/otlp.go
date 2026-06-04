package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

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
	IntValue    *int64 `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool  `json:"boolValue,omitempty"`
}

type otlpAttr struct {
	Key   string        `json:"key"`
	Value otlpAnyValue  `json:"value"`
}

type otlpAnyValue struct {
	StringValue string  `json:"stringValue"`
	IntValue    *int64  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
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
				rawLine := decodeOTLPBody(&lr.Body)

				ts, _ := normalizeTimestamp(lr.TimeUnixNano, "unix_ns_str")

				meta := make(map[string]string)
				for _, attr := range lr.Attributes {
					meta[attr.Key] = formatOTLPAttrValue(&attr.Value)
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

func decodeOTLPBody(b *otlpBody) string {
	if b.StringValue != "" {
		return b.StringValue
	}
	if b.BytesValue != "" {
		decoded, err := base64.StdEncoding.DecodeString(b.BytesValue)
		if err != nil {
			return b.BytesValue
		}
		return string(decoded)
	}
	if b.IntValue != nil {
		return strconv.FormatInt(*b.IntValue, 10)
	}
	if b.DoubleValue != nil {
		return strconv.FormatFloat(*b.DoubleValue, 'f', -1, 64)
	}
	if b.BoolValue != nil {
		return strconv.FormatBool(*b.BoolValue)
	}
	return ""
}

func formatOTLPAttrValue(v *otlpAnyValue) string {
	if v.StringValue != "" {
		return v.StringValue
	}
	if v.IntValue != nil {
		return strconv.FormatInt(*v.IntValue, 10)
	}
	if v.DoubleValue != nil {
		return strconv.FormatFloat(*v.DoubleValue, 'f', -1, 64)
	}
	if v.BoolValue != nil {
		return strconv.FormatBool(*v.BoolValue)
	}
	return ""
}

func (a *OTLPAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, `{"partialSuccess":{}}`)
}
