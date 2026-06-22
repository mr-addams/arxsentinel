// ========================== pkg/processor/chaincheck — Processor ===========================
//   ChainCheckProcessor wraps internal/core/chaincheck.Checker as a plugin.Processor.
//   It enriches LogEntry with ChainIssue when the client IP is a Cloudflare range
//   or a bogon address — indicating a broken proxy chain.
//
//   WHAT IS HERE:
//     ChainCheckProcessor   — plugin.Processor implementation
//     NewChainCheckProcessor — constructor (accepts ctx for the background refresh loop)
//
//   WHAT IS NOT HERE:
//     Manifest              — manifest.go
//     Registration          — register.go

package chaincheck

import (
	"context"

	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ChainCheckProcessor enriches LogEntry with chain integrity findings.
// Never drops entries — always returns the entry (possibly modified).
type ChainCheckProcessor struct {
	checker *chaincheck.Checker
}

// NewChainCheckProcessor creates a checker with the given config.
// The ctx controls the Cloudflare refresh loop lifecycle — when ctx is cancelled
// the background refresh goroutine is stopped.
func NewChainCheckProcessor(ctx context.Context, cfg chaincheck.Config) *ChainCheckProcessor {
	return &ChainCheckProcessor{
		checker: chaincheck.NewChecker(ctx, cfg),
	}
}

// Name returns the processor identifier used in logs and metrics.
func (p *ChainCheckProcessor) Name() string {
	return "chaincheck"
}

// Process checks the entry's RealIP (fallback to RemoteAddr) against
// Cloudflare and bogon ranges. On match, fills entry.ChainIssue.
// Always returns the entry — this processor never drops entries.
// ctx is unused: Checker.Check is a pure function with no I/O or goroutines.
func (p *ChainCheckProcessor) Process(_ context.Context, entry *plugin.LogEntry) (*plugin.LogEntry, error) {
	ip := entry.RealIP
	if ip == "" {
		ip = entry.RemoteAddr
	}

	result := p.checker.Check(ip)
	if result != nil {
		switch result.Kind {
		case "cloudflare":
			entry.ChainIssue = result.Kind + ":" + result.IP + "/" + result.MatchedCIDR
		case "bogon":
			entry.ChainIssue = result.Kind + ":" + result.IP
		}
	}

	return entry, nil
}
