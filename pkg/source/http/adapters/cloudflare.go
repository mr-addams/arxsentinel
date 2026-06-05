// ====== Module: Cloudflare Logpull Adapter ======
// Implements Cloudflare Logpull format (newline-delimited text).
// Includes challenge validation middleware for Cloudflare ownership verification.

package adapters

import (
	"strings"

	nethttp "net/http"
)

// CloudflareAdapter implements Adapter for Cloudflare Logpull API.
// Expects newline-delimited text, returns records without timestamps.
// Called from: buildPushHandler() during HTTP request processing.
type CloudflareAdapter struct{}

// Decode splits body into lines, trims trailing \r, returns as records.
// Non-blocking. Called from: buildPushHandler() to process Cloudflare log stream.
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

// WriteAck writes 200 OK response. Non-blocking.
func (a *CloudflareAdapter) WriteAck(w nethttp.ResponseWriter, meta map[string]string) {
	w.WriteHeader(200)
}

// CloudflareChallengeMiddleware handles Cloudflare ownership challenge validation.
// Responds to GET /?validate=true with Ownership-Challenge header content.
// Called from: buildPushHandler() to add before bearer auth middleware.
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
