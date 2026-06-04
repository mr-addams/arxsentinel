package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	nethttp "net/http"
)

type PubSubAdapter struct{}

type pubSubBody struct {
	Message struct {
		Data      string `json:"data"`
		MessageID string `json:"messageId"`
	} `json:"message"`
}

func (a *PubSubAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	var ps pubSubBody
	if err := json.Unmarshal(body, &ps); err != nil {
		return nil, fmt.Errorf("pubsub: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(ps.Message.Data)
	if err != nil {
		return nil, fmt.Errorf("pubsub: base64 decode: %w", err)
	}
	meta := map[string]string{"messageId": ps.Message.MessageID}
	return []EnvelopeRecord{{RawLine: string(decoded), Metadata: meta}}, nil
}

func (a *PubSubAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(204)
}
