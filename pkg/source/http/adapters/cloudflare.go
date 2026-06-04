package adapters

import (
	"strings"

	nethttp "net/http"
)

type CloudflareAdapter struct{}

func (a *CloudflareAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
	lines := strings.Split(string(body), "\n")
	var records []EnvelopeRecord
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		records = append(records, EnvelopeRecord{RawLine: line})
	}
	return records, nil
}

func (a *CloudflareAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(200)
}

func CloudflareChallengeMiddleware(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method == "GET" && r.URL.Query().Get("validate") == "true" {
			challenge := r.Header.Get("Ownership-Challenge")
			if challenge != "" {
				w.WriteHeader(200)
				w.Write([]byte(challenge))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
