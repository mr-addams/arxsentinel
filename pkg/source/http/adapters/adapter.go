package adapters

import nethttp "net/http"

type Adapter interface {
	Decode(body []byte) ([]EnvelopeRecord, error)
	WriteAck(w nethttp.ResponseWriter, meta map[string]string)
}

type EnvelopeRecord struct {
	RawLine   string
	Timestamp int64
	Metadata  map[string]string
}
