// ====== Module: AWS Kinesis Firehose Adapter ======
// Implements AWS Kinesis Firehose HTTP Endpoint Delivery format.
// Expects JSON array with base64-encoded records.

package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	nethttp "net/http"
)

// init registers the firehose factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("firehose", func(cfg AdapterConfig) (Adapter, error) {
		return &FirehoseAdapter{}, nil
	})
}

// FirehoseAdapter implements Adapter for AWS Kinesis Firehose.
// Expects JSON: {"records":[{"data":"base64..."}]}
// Called from: buildPushHandler() during HTTP request processing.
type FirehoseAdapter struct{}

// firehoseBody represents the AWS Firehose HTTP endpoint delivery format.
type firehoseBody struct {
	Records []struct {
		Data string `json:"data"` // base64-encoded log data
	} `json:"records"`
}

// Decode parses Firehose JSON, decodes base64 data for each record.
// Returns raw decoded lines without timestamps.
// Called from: buildPushHandler() to process Firehose payloads.
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

// WriteAck writes JSON acknowledgment with requestId and timestamp.
// Required by Firehose — client waits for this response before retrying.
// Non-blocking. Called from: buildPushHandler() after successful Decode().
func (a *FirehoseAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	requestID := meta["X-Amz-Firehose-Request-Id"]
	ts := time.Now().UnixMilli()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	// Use json.Encode to prevent JSON injection via requestID containing " or \.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"requestId": requestID,
		"timestamp": ts,
	})
}
