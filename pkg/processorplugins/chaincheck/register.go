// ========================== pkg/processor/chaincheck — Registration ========================
//   Self-registration via init() so the pipeline can instantiate this processor by name.

package chaincheck

import (
	"context"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/processor"
)

func init() {
	processor.Register("chaincheck", factory)
}

// factory converts ProcessorConfig to chaincheck.Config and creates the processor.
// Params expects optional keys: "cloudflare_enabled" (bool), "cloudflare_refresh_interval" (string),
// "cloudflare_sources" ([]any), "bogon_enabled" (bool).
// Uses context.Background() for the Cloudflare refresh loop — by design, the Factory
// signature has no ctx argument. The refresh goroutine lives until process exit.
func factory(cfg processor.ProcessorConfig) (plugin.Processor, error) {
	cfEnabled := boolParam(cfg.Params, "cloudflare_enabled", false)
	bogonEnabled := boolParam(cfg.Params, "bogon_enabled", true)

	interval := durationParam(cfg.Params, "cloudflare_refresh_interval", 24*time.Hour)

	sources := stringSliceParam(cfg.Params, "cloudflare_sources", []string{
		"https://www.cloudflare.com/ips-v4/",
		"https://www.cloudflare.com/ips-v6/",
	})

	ccfg := chaincheck.Config{
		Cloudflare: chaincheck.CloudflareConfig{
			Enabled:         cfEnabled,
			RefreshInterval: interval,
			Sources:         sources,
		},
		Bogon: chaincheck.BogonConfig{
			Enabled: bogonEnabled,
		},
	}

	p := NewChainCheckProcessor(context.Background(), ccfg)
	return p, nil
}

// boolParam extracts a bool from Params or returns fallback.
func boolParam(params map[string]any, key string, fallback bool) bool {
	if params == nil {
		return fallback
	}
	v, ok := params[key]
	if !ok {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

// durationParam extracts a duration string from Params or returns fallback.
func durationParam(params map[string]any, key string, fallback time.Duration) time.Duration {
	if params == nil {
		return fallback
	}
	v, ok := params[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// stringSliceParam extracts a []string from Params (supports YAML list → []any) or returns fallback.
func stringSliceParam(params map[string]any, key string, fallback []string) []string {
	if params == nil {
		return fallback
	}
	v, ok := params[key]
	if !ok {
		return fallback
	}
	raw, ok := v.([]any)
	if !ok {
		return fallback
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// Ensure factory satisfies the expected signature at compile time.
var _ processor.Factory = factory

// Ensure ChainCheckProcessor satisfies plugin.Processor at compile time.
var _ plugin.Processor = (*ChainCheckProcessor)(nil)
