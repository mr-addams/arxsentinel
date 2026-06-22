// ====== Module: GCP Pub/Sub Push Adapter ======
// Implements Google Cloud Pub/Sub push subscription format.
// Expects JSON with message.data (base64.RawURLEncoding) and messageId.

package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	nethttp "net/http"
)

// init registers the pubsub factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("pubsub", func(cfg AdapterConfig) (Adapter, error) {
		return &PubSubAdapter{}, nil
	})
}

// PubSubAdapter implements Adapter for GCP Pub/Sub push subscriptions.
// Expects JSON: {"message":{"data":"base64url...","messageId":"..."}}
// Called from: buildPushHandler() during HTTP request processing.
type PubSubAdapter struct{}

// pubSubBody represents GCP Pub/Sub push message format.
type pubSubBody struct {
	Message struct {
		Data      string `json:"data"`      // YAML: base64.RawURLEncoding encoded payload
		MessageID string `json:"messageId"` // YAML: GCP-assigned message ID
	} `json:"message"`
}

// Decode parses Pub/Sub push JSON, decodes base64.RawURLEncoding data.
// Populates Metadata with messageId for tracking.
// Called from: buildPushHandler() to process Pub/Sub push payloads.
func (a *PubSubAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var ps pubSubBody
	if err := json.Unmarshal(body, &ps); err != nil {
		return nil, fmt.Errorf("pubsub: %w", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(ps.Message.Data)
	if err != nil {
		return nil, fmt.Errorf("pubsub: base64 decode: %w", err)
	}
	meta := map[string]string{"messageId": ps.Message.MessageID}
	return []EnvelopeRecord{{RawLine: string(decoded), Metadata: meta}}, nil
}

// WriteAck writes 204 No Content response. Non-blocking.
func (a *PubSubAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
