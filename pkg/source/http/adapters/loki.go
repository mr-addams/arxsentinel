package adapters

import (
	"encoding/json"
	"fmt"
	"strconv"

	nethttp "net/http"
)

type LokiAdapter struct{}

type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

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

func (a *LokiAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
