package http

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
	"github.com/mr-addams/arxsentinel/pkg/source/http/adapters"
	nethttp "net/http"
)

func runPush(ctx context.Context, cfg *parsedConfig, handler nethttp.Handler) error {
	server := &nethttp.Server{
		Addr:    cfg.host + ":" + cfg.port,
		Handler: handler,
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

func bearerAuth(token string, next nethttp.Handler) nethttp.Handler {
	if token == "" {
		return next
	}
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 7 || auth[:7] != "Bearer " {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) != 1 {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func buildPushHandler(cfg *parsedConfig, adapter adapters.Adapter, out chan<- *plugin.LogEntry, par pkgsource.LineParser, logFn func(string, string, string), maxBodyBytes int64, counters *sourceCounters) nethttp.Handler {
	var h nethttp.Handler
	h = nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, err := readLimited(r.Body, maxBodyBytes)
		if err != nil {
			nethttp.Error(w, "request body too large", 413)
			return
		}

		body, err = maybeGunzip(body, r.Header.Get("Content-Encoding"), maxBodyBytes)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}

		if cfg.proto == protocolLoki || cfg.proto == protocolOTLP {
			if r.Header.Get("Content-Type") == "application/x-protobuf" {
				nethttp.Error(w, "unsupported content type: application/x-protobuf", 415)
				return
			}
		}

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
			select {
			case out <- entry:
				atomic.AddInt64(&counters.linesRead, 1)
			default:
				atomic.AddInt64(&counters.dropped, 1)
			}
		}

		adapter.WriteAck(w, meta)
	})

	handler := bearerAuth(cfg.token, h)
	handler = adapters.CloudflareChallengeMiddleware(handler)
	if cfg.proto == protocolPubSub {
		handler = adapters.PubSubJWTMiddleware(handler)
	}

	return handler
}

func writeJSON(w nethttp.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}