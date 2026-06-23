// ====== Module: Cloudflare Logpull Adapter ======
// Implements Cloudflare Logpull format (newline-delimited text).
// Includes challenge validation middleware for Cloudflare ownership verification.

package adapters

import (
	"strings"

	nethttp "net/http"
)

// init registers the cloudflare factory with the open adapter registry.
// Called from: package init order during program startup. Non-blocking.
func init() {
	Register("cloudflare", func(cfg AdapterConfig) (Adapter, error) {
		return &CloudflareAdapter{}, nil
	})
}

// isValidChallenge проверяет, что challenge содержит только разрешённые
// символы: буквы латиницы, цифры, точка, подчёркивание, дефис.
// Используется в CloudflareChallengeMiddleware (H3) для предотвращения
// инъекции произвольного содержимого в HTTP-ответ.
func isValidChallenge(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b >= '0' && b <= '9':
		case b == '.' || b == '_' || b == '-':
		default:
			return false
		}
	}
	return true
}

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
			if challenge == "" {
				next.ServeHTTP(w, r)
				return
			}
			// H3: валидация challenge — только [a-zA-Z0-9._-]+
			// Предотвращает инъекцию произвольного содержимого в ответ.
			if !isValidChallenge(challenge) {
				nethttp.Error(w, "invalid challenge format", 400)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			w.Write([]byte(challenge))
			return
		}
		next.ServeHTTP(w, r)
	})
}
