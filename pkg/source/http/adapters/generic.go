package adapters

import (
	"encoding/json"
	"strings"

	nethttp "net/http"
)

type GenericAdapter struct {
	field    string
	isNDJSON bool
}

func New(field string, isNDJSON bool) *GenericAdapter {
	return &GenericAdapter{field: field, isNDJSON: isNDJSON}
}

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

func (a *GenericAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(200)
}
