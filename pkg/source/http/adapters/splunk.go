package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	nethttp "net/http"
)

type SplunkAdapter struct{}

type splunkEvent struct {
	Time  *float64        `json:"time"`
	Event json.RawMessage `json:"event"`
}

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
			rawLine = string(se.Event)
		}
		var ts int64
		if se.Time != nil {
			ts, _ = normalizeTimestamp(strconv.FormatFloat(*se.Time, 'f', -1, 64), "unix_float") // per-record best-effort; 0 if unparseable
		}
		records = append(records, EnvelopeRecord{RawLine: rawLine, Timestamp: ts})
	}
	return records, nil
}

func (a *SplunkAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, `{"text":"Success","code":0}`)
}
