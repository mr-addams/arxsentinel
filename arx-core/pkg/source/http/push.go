// ====== Module: HTTP Push Server ======
// Implements HTTP webhook server for receiving log events via push mode.
// Handles TLS, authentication, middleware chain, and request routing.

package http

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
	"github.com/mr-addams/arx-core/pkg/source/http/adapters"
	nethttp "net/http"
)

// runPush starts the HTTP server in push (webhook) mode.
// Listens on host:port with optional TLS, shuts down gracefully on ctx cancel.
// Called from: HTTPSource.Run() when mode == "push". Non-blocking.
func runPush(ctx context.Context, cfg *parsedConfig, handler nethttp.Handler) error {
	server := &nethttp.Server{
		Addr:              cfg.host + ":" + cfg.port,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.scheme == "https" {
		cert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return fmt.Errorf("http source: load TLS cert: %w", err)
		}
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutCtx)
	}()

	var err error
	if cfg.scheme == "https" {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err == nethttp.ErrServerClosed {
		return nil
	}
	return err
}

// bearerAuth wraps handler with Bearer token authentication.
// Returns original handler if token is empty (no auth required).
// Called from: buildPushHandler() to add auth middleware.
func bearerAuth(token string, next nethttp.Handler) nethttp.Handler {
	if token == "" {
		return next
	}
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		// Constant-time comparison prevents timing attacks on token validation.
		// Compare the full "Bearer <token>" string including the prefix.
		expected := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildPushHandler creates HTTP handler with protocol-specific processing.
// Assembles middleware chain: optional vendor-specific middleware → bearer auth → pubsub jwt → request handler.
// Non-blocking. Called from: HTTPSource.Run().
func buildPushHandler(cfg *parsedConfig, adapter adapters.Adapter, out chan<- *plugin.Event, par pkgsource.LineParser, logFn func(string, string, string), maxBodyBytes int64, counters *sourceCounters) nethttp.Handler {
	var h nethttp.Handler
	h = nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, err := readLimited(r.Body, maxBodyBytes)
		if err != nil {
			nethttp.Error(w, "request body too large", 413)
			return
		}

		// Gunzip if Content-Encoding: gzip, but only if result stays within limit.
		body, err = maybeGunzip(body, r.Header.Get("Content-Encoding"), maxBodyBytes)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}

		// Reject protobuf for Loki/OTLP — we only handle JSON.
		if cfg.proto == "loki" || cfg.proto == "otlp" {
			if r.Header.Get("Content-Type") == "application/x-protobuf" {
				nethttp.Error(w, "unsupported content type: application/x-protobuf", 415)
				return
			}
		}

		// Preserve vendor request IDs for tracing.
		meta := make(map[string]string)
		if rid := r.Header.Get("X-Amz-Firehose-Request-Id"); rid != "" {
			meta["X-Amz-Firehose-Request-Id"] = rid
		}
		if rid := r.Header.Get("X-Request-ID"); rid != "" {
			meta["X-Request-ID"] = rid
		}

		records, err := adapter.Decode(body)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}

		for _, record := range records {
			entry, ok := par.Parse(record.RawLine)
			if !ok {
				atomic.AddInt64(&counters.parseErrors, 1)
				continue
			}
			// Phase 2.2 (Flow 083): the source-emitter channel now carries
			// *plugin.Event. We wrap the parsed LogEntry into an Event with
			// a transport Envelope. Source is the remote peer (best signal of
			// origin at this stage); SourceType identifies the HTTP transport;
			// Stream is empty (pipeline stream is assigned downstream);
			// Timestamp is the parsed request time.
			event := parser.WrapLogEntry(entry, plugin.Envelope{
				Source:     entry.RemoteAddr,
				SourceType: "http",
				Timestamp:  entry.Time,
			})
			select {
			case out <- event:
				atomic.AddInt64(&counters.linesRead, 1)
			default:
				// Non-blocking send — drop if channel is full.
				atomic.AddInt64(&counters.dropped, 1)
			}
		}

		adapter.WriteAck(w, meta)
	})

	handler := bearerAuth(cfg.token, h)
	handler = adapters.CloudflareChallengeMiddleware(handler)
	if cfg.proto == "pubsub" {
		// PubSub requires JWT validation — build endpoint URL for audience claim.
		// bearerAuth above also checks cfg.token if set (smoke-test / compat mode).
		// Two gates are intentional: bearerAuth catches rogue plain-Bearer traffic early,
		// PubSubJWTMiddleware handles the OIDC JWT path. Both must pass.
		endpointURL := cfg.scheme + "://" + cfg.host + ":" + cfg.port + cfg.path
		handler = adapters.PubSubJWTMiddleware(endpointURL, cfg.token, handler)
	}

	return handler
}

// writeJSON writes a JSON response with specified HTTP status code.
// Helper for writing error responses. Non-blocking.
func writeJSON(w nethttp.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
