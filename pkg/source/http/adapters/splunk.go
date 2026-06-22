// ====== Module: Splunk HTTP Event Collector Adapter ======
// Implements Splunk HEC JSON format (newline-delimited JSON events).
// Parses time field (unix_float) and event field from each JSON object.

package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	nethttp "net/http"
)

// init registers the splunk factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("splunk", func(cfg AdapterConfig) (Adapter, error) {
		return &SplunkAdapter{}, nil
	})
}

// SplunkAdapter implements Adapter for Splunk HTTP Event Collector.
// Expects newline-delimited JSON: {"time":123.456,"event":"log line"}
// Called from: buildPushHandler() during HTTP request processing.
type SplunkAdapter struct{}

// splunkEvent represents Splunk HEC event format.
type splunkEvent struct {
	Time  *float64        `json:"time"`  // YAML: Unix timestamp as float (e.g., 1234.567)
	Event json.RawMessage `json:"event"` // YAML: log event content (string or object)
}

// Decode parses Splunk HEC JSON, extracts time and event from each line.
// Uses streaming decoder for memory efficiency with large payloads.
// Called from: buildPushHandler() to process Splunk HEC payloads.
func (a *SplunkAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var records []EnvelopeRecord
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var se splunkEvent
		if err := dec.Decode(&se); err != nil {
			return nil, fmt.Errorf("splunk: %w", err)
		}
		rawLine := ""
		if se.Event != nil {
			var s string
			if err := json.Unmarshal(se.Event, &s); err == nil {
				rawLine = s
			} else {
				rawLine = string(se.Event)
			}
		}
		var ts int64
		if se.Time != nil {
			ts, _ = normalizeTimestamp(strconv.FormatFloat(*se.Time, 'f', -1, 64), "unix_float") // per-record best-effort; 0 if unparseable
		}
		records = append(records, EnvelopeRecord{RawLine: rawLine, Timestamp: ts})
	}
	return records, nil
}

// WriteAck writes JSON acknowledgment with success status.
// Required by Splunk HEC — client waits for this response.
// Non-blocking. Called from: buildPushHandler() after successful Decode().
func (a *SplunkAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, `{"text":"Success","code":0}`)
}
