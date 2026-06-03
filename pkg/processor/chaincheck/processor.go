// ========================== pkg/processor/chaincheck — Processor ===========================
//   ChainCheckProcessor wraps internal/core/chaincheck.Checker as a plugin.Processor.
//   It enriches LogEntry with ChainIssue when the client IP is a Cloudflare range
//   or a bogon address — indicating a broken proxy chain.
//
//   WHAT IS HERE:
//     ChainCheckProcessor   — plugin.Processor implementation
//     NewChainCheckProcessor — constructor
//
//   WHAT IS NOT HERE:
//     Manifest              — manifest.go
//     Registration          — register.go

package chaincheck

import (
	"context"

	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ChainCheckProcessor enriches LogEntry with chain integrity findings.
// Never drops entries — always returns the entry (possibly modified).
type ChainCheckProcessor struct {
	checker *chaincheck.Checker
}

// NewChainCheckProcessor creates a checker with the given config.
// Uses context.Background() for the Cloudflare refresh loop lifecycle.
func NewChainCheckProcessor(cfg chaincheck.Config) *ChainCheckProcessor {
	return &ChainCheckProcessor{
		checker: chaincheck.NewChecker(context.Background(), cfg),
	}
}

// Name returns the processor identifier used in logs and metrics.
func (p *ChainCheckProcessor) Name() string {
	return "chaincheck"
}

// Process checks the entry's RealIP (fallback to RemoteAddr) against
// Cloudflare and bogon ranges. On match, fills entry.ChainIssue.
// Always returns the entry — this processor never drops entries.
func (p *ChainCheckProcessor) Process(entry *plugin.LogEntry) (*plugin.LogEntry, error) {
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