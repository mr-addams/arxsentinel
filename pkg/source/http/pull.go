package http

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
	"github.com/mr-addams/arxsentinel/pkg/source/http/adapters"
	nethttp "net/http"
)

func runPull(ctx context.Context, cfg *parsedConfig, adapter adapters.Adapter, out chan<- *plugin.LogEntry, par pkgsource.LineParser, logFn func(string, string, string), counters *sourceCounters) error {
	ticker := time.NewTicker(cfg.pullInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			req, err := nethttp.NewRequestWithContext(ctx, "GET", cfg.scheme+"://"+cfg.host+":"+cfg.port+cfg.path, nil)
			if err != nil {
				if logFn != nil {
					logFn("HTTP", fmt.Sprintf("pull: build request: %v", err), "error")
				}
				continue
			}
			if cfg.token != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.token)
			}

			resp, err := nethttp.DefaultClient.Do(req)
			if err != nil {
				if logFn != nil {
					logFn("HTTP", fmt.Sprintf("pull: request failed: %v", err), "error")
				}
				continue
			}

			body, err := readLimited(resp.Body, cfg.maxBodyBytes)
			resp.Body.Close()
			if err != nil {
				if logFn != nil {
					logFn("HTTP", fmt.Sprintf("pull: read body: %v", err), "error")
				}
				continue
			}

			body, err = maybeGunzip(body, resp.Header.Get("Content-Encoding"), cfg.maxBodyBytes)
			if err != nil {
				if logFn != nil {
					logFn("HTTP", fmt.Sprintf("pull: gunzip: %v", err), "error")
				}
				continue
			}

			records, err := adapter.Decode(body)
			if err != nil {
				if logFn != nil {
					logFn("HTTP", fmt.Sprintf("pull: decode: %v", err), "error")
				}
				continue
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

		case <-ctx.Done():
			return nil
		}
	}
}

