// ====== Module: Generic HTTP Adapter ======
// Implements plain and NDJSON formats for generic HTTP log ingestion.
// Supports optional field extraction from NDJSON objects.

package adapters

import (
	"encoding/json"
	"strings"

	nethttp "net/http"
)

// init registers the plain and ndjson factories with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("plain", func(cfg AdapterConfig) (Adapter, error) {
		return New("", false), nil
	})
	Register("ndjson", func(cfg AdapterConfig) (Adapter, error) {
		return New(cfg.EnvelopeField, true), nil
	})
}

// GenericAdapter implements Adapter for plain and NDJSON HTTP formats.
// field: JSON key to extract from each NDJSON object (empty = whole line).
// isNDJSON: true for newline-delimited JSON, false for plain text.
// Called from: buildPushHandler() for the "plain" and "ndjson" protocols.
type GenericAdapter struct {
	field    string // YAML: envelope_field — JSON key to extract. Consumer: Decode()
	isNDJSON bool   // YAML: ndjson mode flag. Consumer: Decode()
}

// New creates a GenericAdapter with specified field extraction and NDJSON mode.
// Factory function — no side effects. Non-blocking.
func New(field string, isNDJSON bool) *GenericAdapter {
	return &GenericAdapter{field: field, isNDJSON: isNDJSON}
}

// Decode parses body as plain text or NDJSON based on isNDJSON flag.
// For NDJSON with field: extracts specified JSON field from each line.
// For NDJSON without field: uses whole JSON line as RawLine.
// For plain: splits on newlines, trims \r, returns non-empty lines.
// Called from: buildPushHandler() to process generic HTTP log payloads.
func (a *GenericAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	if a.isNDJSON {
		lines := strings.Split(string(body), "\n")
		var records []EnvelopeRecord
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			if a.field != "" {
				var raw map[string]json.RawMessage
				if err := json.Unmarshal([]byte(line), &raw); err != nil {
					return nil, err
				}
				val, ok := raw[a.field]
				if !ok {
					// Field missing — use whole line (fallback).
					records = append(records, EnvelopeRecord{RawLine: line})
					continue
				}
				var s string
				if err := json.Unmarshal(val, &s); err != nil {
					records = append(records, EnvelopeRecord{RawLine: string(val)})
				} else {
					records = append(records, EnvelopeRecord{RawLine: s})
				}
			} else {
				records = append(records, EnvelopeRecord{RawLine: line})
			}
		}
		return records, nil
	}

	lines := strings.Split(string(body), "\n")
	var records []EnvelopeRecord
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			records = append(records, EnvelopeRecord{RawLine: line})
		}
	}
	return records, nil
}

// WriteAck writes 200 OK response. Non-blocking.
func (a *GenericAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(200)
}
