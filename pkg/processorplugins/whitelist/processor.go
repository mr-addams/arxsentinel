// ========================== Module pkg/processor/whitelist ================================
//   WhitelistProcessor wraps internal/core/whitelist (Matcher + Verifier) as a plugin.Processor.
//   Drops whitelisted IPs/UAs, verifies legitimate bot UAs via rDNS+fDNS, and passes
//   identified fake bots to the scoring pipeline.
//
//   WHAT IS HERE:
//     - WhitelistProcessor — plugin.Processor implementation
//     - NewWhitelistProcessor — constructor from config
//
//   WHAT IS NOT HERE:
//     - Matcher / Verifier / IPCache — internal/core/whitelist/ (unchanged, not moved)
//     - main.go integration — the processor replaces inline whitelist calls
//
//   PIPELINE SEMANTICS:
//     - Process returns (nil, nil) → drop entry (custom whitelist hit)
//     - Process returns (*LogEntry, nil) → pass through (bot verified or no match)
//     - Process returns (nil, ctx.Err()) → cancellation honored
//     - Fake bots pass through so detectors can add FakeBotScore

package whitelist

import (
	"context"
	"fmt"
	"time"

	corewhitelist "github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// WhitelistProcessor is a plugin.Processor that wraps Matcher + Verifier.
type WhitelistProcessor struct {
	matcher    *corewhitelist.Matcher
	verifier   *corewhitelist.Verifier
	dnsTimeout time.Duration
}

// NewWhitelistProcessor creates a WhitelistProcessor from config.
// resolver is injected for testability; production passes &net.Resolver{PreferGo: true}.
func NewWhitelistProcessor(cfg config.WhitelistConfig, resolver corewhitelist.Resolver) (*WhitelistProcessor, error) {
	matcher, err := corewhitelist.NewMatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("whitelist: create matcher: %w", err)
	}
	cache := corewhitelist.NewIPCache(cfg.DNSCache)
	verifier := corewhitelist.NewVerifier(cache, resolver, nil)
	return &WhitelistProcessor{
		matcher:    matcher,
		verifier:   verifier,
		dnsTimeout: time.Duration(cfg.DNSVerifyTimeout),
	}, nil
}

// Name returns "whitelist".
func (p *WhitelistProcessor) Name() string {
	return "whitelist"
}

// Manifest returns the plugin manifest.
func (p *WhitelistProcessor) Manifest() plugin.Manifest {
	return Manifest
}

// Process applies whitelist filtering to a log entry.
//
// Order of checks:
//  1. IsWhitelistedIP → drop (nil, nil)
//  2. IsWhitelistedUA → drop (nil, nil)
//  3. MatchBot → Verify over DNS; fake bots pass through, verified bots pass through
//  4. No match → pass through
//
// ctx is used for the DNS verification deadline (derived timeout).
// Respects cancellation: returns (nil, ctx.Err()) when ctx is done.
func (p *WhitelistProcessor) Process(ctx context.Context, entry *plugin.LogEntry) (*plugin.LogEntry, error) {
	// ── Respect cancellation ──────────────────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ── Custom whitelist: IP/CIDR ──────────────────────────────────────────────────────
	if p.matcher.IsWhitelistedIP(entry.RealIP) {
		return nil, nil
	}

	// ── Custom whitelist: UA substring ─────────────────────────────────────────────────
	if p.matcher.IsWhitelistedUA(entry.UserAgent) {
		return nil, nil
	}

	// ── Bot UA match → DNS verification ──────────────────────────────────────────────
	if _, botCfg, matched := p.matcher.MatchBot(entry.UserAgent); matched {
		vctx, cancel := context.WithTimeout(ctx, p.dnsTimeout)
		defer cancel()
		p.verifier.Verify(vctx, entry.RealIP, botCfg)
	}

	return entry, nil
}
