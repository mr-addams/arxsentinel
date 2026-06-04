package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	nethttp "net/http"
)

type FirehoseAdapter struct{}

type firehoseBody struct {
	Records []struct {
		Data string `json:"data"`
	} `json:"records"`
}

func (a *FirehoseAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var fb firehoseBody
	if err := json.Unmarshal(body, &fb); err != nil {
		return nil, fmt.Errorf("firehose: %w", err)
	}
	records := make([]EnvelopeRecord, 0, len(fb.Records))
	for _, r := range fb.Records {
		decoded, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, fmt.Errorf("firehose: base64 decode: %w", err)
		}
		records = append(records, EnvelopeRecord{RawLine: string(decoded)})
	}
	return records, nil
}

func (a *FirehoseAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	requestID := meta["X-Amz-Firehose-Request-Id"]
	ts := time.Now().UnixMilli()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprintf(w, `{"requestId":"%s","timestamp":%d}`, requestID, ts)
}
