// ====== Module: OpenTelemetry Protocol (OTLP) Adapter ======
// Implements OTLP HTTP JSON log format (protobuf not supported).
// Parses ResourceLogs → ScopeLogs → LogRecords hierarchy.

package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	nethttp "net/http"
)

// init registers the otlp factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("otlp", func(cfg AdapterConfig) (Adapter, error) {
		return &OTLPAdapter{}, nil
	})
}

// OTLPAdapter implements Adapter for OpenTelemetry Protocol (logs).
// Expects JSON format (not protobuf) with ResourceLogs structure.
// Called from: buildPushHandler() during HTTP request processing.
type OTLPAdapter struct{}

// otlpRequest represents OTLP JSON logs request format.
type otlpRequest struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

// resourceLogs wraps scope logs under a resource.
type resourceLogs struct {
	ScopeLogs []scopeLogs `json:"scopeLogs"`
}

// scopeLogs contains a list of log records from a scope.
type scopeLogs struct {
	LogRecords []logRecord `json:"logRecords"`
}

// logRecord represents a single OTLP log entry.
type logRecord struct {
	TimeUnixNano string     `json:"timeUnixNano"` // YAML: Unix nanoseconds as string
	Body         otlpBody   `json:"body"`         // YAML: log body (one of stringValue, bytesValue, etc.)
	Attributes   []otlpAttr `json:"attributes"`   // YAML: key-value metadata pairs
}

// otlpBody represents OTLP AnyValue — supports string, bytes, int, double, bool.
type otlpBody struct {
	StringValue string   `json:"stringValue"` // YAML: plain string log line
	BytesValue  string   `json:"bytesValue"`  // YAML: base64-encoded string
	IntValue    *int64   `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

// otlpAttr represents OTLP attribute key-value pair.
type otlpAttr struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue represents OTLP AnyValue — supports all primitive types.
type otlpAnyValue struct {
	StringValue string   `json:"stringValue"`
	IntValue    *int64   `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

// Decode parses OTLP JSON, extracts log records with timestamps and attributes.
// Populates Metadata with log attributes for downstream processing.
// Called from: buildPushHandler() to process OTLP log payloads.
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

// decodeOTLPBody extracts string value from OTLP body (one of: string, bytes, int, double, bool).
// Non-blocking. Called from: Decode().
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

// formatOTLPAttrValue converts OTLP AnyValue to string for metadata map.
// Non-blocking. Called from: Decode().
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

// WriteAck writes JSON acknowledgment with empty partialSuccess.
// OTLP requires Content-Type header and acknowledgment response.
// Non-blocking. Called from: buildPushHandler() after successful Decode().
func (a *OTLPAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, `{"partialSuccess":{}}`)
}
