// ========================== Module chaincheck/cloudflare =================================
//   CloudflareChecker: dynamic detection of Cloudflare IP ranges.
//   Loads fallback CIDRs synchronously at construction, then refreshes from upstream
//   sources on a ticker. Uses sync.RWMutex because reads (Contains) are frequent and
//   concurrent while writes (refresh) are rare and happen in a single background goroutine.
//
//   WHAT IS HERE:
//     CloudflareChecker — dynamic CIDR list with background refresh
//     NewCloudflareChecker() — synchronous fallback load + goroutine start
//     Contains()  — concurrent-safe range lookup
//     IsLoaded()  — reports whether at least fallback CIDRs are available
//     Update()    — hot-reload on SIGHUP: replaces config and restarts goroutine
//     Close()     — stops the refresh goroutine
//
//   WHAT IS NOT HERE:
//     Bogon detection (bogon.go)
//     Orchestration / caller logic (checker.go)
//
//   HTTP CONSTRAINTS:
//     - io.LimitReader 64 KB per response — prevents memory exhaustion from a rogue source
//     - 30s HTTP timeout — avoids blocking the refresh goroutine indefinitely
//     - On fetch error: old nets are preserved, error is logged via utils.Log

package chaincheck

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// fallbackCloudflareV4 holds known Cloudflare IPv4 CIDRs as of May 2026.
// Sourced from https://www.cloudflare.com/ips-v4/ — refreshed at runtime via Sources.
// Used as the initial set so the checker works immediately without a network request.
var fallbackCloudflareV4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// fallbackCloudflareV6 holds known Cloudflare IPv6 CIDRs as of May 2026.
// Sourced from https://www.cloudflare.com/ips-v6/
var fallbackCloudflareV6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

const (
	// fetchLimitBytes caps each HTTP response to 64 KB.
	// This is a security invariant, not a tunable parameter: Cloudflare publishes
	// ~15 IPv4 + ~7 IPv6 CIDRs (< 512 bytes total). 64 KB gives 100× headroom for
	// future growth while keeping the upper bound well below any meaningful memory pressure.
	// Making this configurable would invite misconfiguration without meaningful benefit.
	fetchLimitBytes = 64 * 1024

	// httpTimeout is applied to every individual fetch request.
	// 30s is intentionally generous — CIDR lists are tiny and fast to download,
	// but the source may be behind a slow CDN or rate-limited.
	httpTimeout = 30 * time.Second
)

// CloudflareConfig holds the configuration for CloudflareChecker.
//
// YAML: chain_guard.cloudflare.enabled, chain_guard.cloudflare.refresh_interval, chain_guard.cloudflare.sources[].
// Consumer: NewCloudflareChecker, Update.
type CloudflareConfig struct {
	Enabled         bool          // YAML: chain_guard.cloudflare.enabled, default false. Consumer: NewCloudflareChecker, Update.
	RefreshInterval time.Duration // YAML: chain_guard.cloudflare.refresh_interval. Consumer: startRefreshLoop.
	Sources         []string      // YAML: chain_guard.cloudflare.sources[]. Consumer: fetchAll.
}

// CloudflareChecker detects whether an IP belongs to a Cloudflare-owned range.
// The CIDR list is refreshed from upstream sources on a background ticker.
// sync.RWMutex allows concurrent Contains() calls with minimal contention.
//
// YAML: chain_guard.cloudflare.*. Consumer: checker.go (Check).
type CloudflareChecker struct {
	mu     sync.RWMutex
	nets   []*net.IPNet           // Internal — compiled Cloudflare CIDRs, replaced on refresh. Consumer: Contains, IsLoaded.
	cfg    CloudflareConfig        // YAML: current config. Consumer: startRefreshLoop, fetchAll.
	client *http.Client           // Internal — HTTP client with 30s timeout. Consumer: fetchSource.

	cancel context.CancelFunc      // Internal — cancels the refresh goroutine. Consumer: stopRefreshLoop, Update.
	done   chan struct{}           // Internal — closed when the goroutine exits. Consumer: stopRefreshLoop.
}

// NewCloudflareChecker loads the fallback CIDRs synchronously so that IsLoaded()
// returns true immediately, then starts the refresh goroutine.
// The goroutine stops when ctx is cancelled or Close() is called.
//
// Called from: checker.go (NewChecker).
// Non-blocking: fallback load is sync, goroutine is async.
func NewCloudflareChecker(ctx context.Context, cfg CloudflareConfig) *CloudflareChecker {
	c := &CloudflareChecker{
		cfg:    cfg,
		client: &http.Client{Timeout: httpTimeout},
	}
	// Load fallback CIDRs before starting the goroutine so the checker is
	// immediately usable without a network round-trip on startup.
	c.nets = parseCIDRList(append(fallbackCloudflareV4, fallbackCloudflareV6...))

	if cfg.Enabled {
		c.startRefreshLoop(ctx)
	}
	return c
}

// startRefreshLoop starts the background refresh goroutine.
// Must be called with c.cancel == nil or after the previous goroutine has exited.
func (c *CloudflareChecker) startRefreshLoop(ctx context.Context) {
	loopCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})

	go func() {
		defer close(c.done)
		ticker := time.NewTicker(c.cfg.RefreshInterval)
		defer ticker.Stop()

		// Fetch immediately on start rather than waiting for the first tick.
		// This ensures fresh data is loaded as soon as the checker starts (or restarts on SIGHUP).
		c.fetchAll(loopCtx)

		for {
			select {
			case <-ticker.C:
				c.fetchAll(loopCtx)
			case <-loopCtx.Done():
				return
			}
		}
	}()
}

// Contains reports whether ip belongs to any known Cloudflare CIDR.
// Returns (true, matchedCIDR) on match, (false, "") otherwise.
// A nil ip always returns false — no panic.
//
// Called from: checker.go (Check).
// Non-blocking: read lock only.
func (c *CloudflareChecker) Contains(ip net.IP) (bool, string) {
	if ip == nil {
		return false, ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, network := range c.nets {
		if network.Contains(ip) {
			return true, network.String()
		}
	}
	return false, ""
}

// IsLoaded reports whether at least the fallback CIDRs have been loaded.
// Always true after NewCloudflareChecker returns.
//
// Called from: tests, pipeline (main.go).
// Non-blocking: read lock only.
func (c *CloudflareChecker) IsLoaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.nets) > 0
}

// Update replaces the config and restarts the refresh goroutine.
// Called on SIGHUP to apply new source URLs or refresh interval without restarting the process.
func (c *CloudflareChecker) Update(ctx context.Context, cfg CloudflareConfig) {
	// Stop the current goroutine before replacing cfg to avoid a race
	// where the old goroutine reads cfg while we are writing it.
	c.stopRefreshLoop()

	c.cfg = cfg
	if cfg.Enabled {
		c.startRefreshLoop(ctx)
	}
}

// Close stops the refresh goroutine. Safe to call multiple times.
func (c *CloudflareChecker) Close() {
	c.stopRefreshLoop()
}

// stopRefreshLoop cancels the context and waits for the goroutine to exit.
// No-op if the goroutine was never started.
func (c *CloudflareChecker) stopRefreshLoop() {
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.done != nil {
		<-c.done
		c.done = nil
	}
}

// fetchAll fetches CIDRs from all configured sources and replaces c.nets.
// On any fetch error the old nets are preserved — partial failures are logged but non-fatal.
// This means Cloudflare protection degrades gracefully to the last successful fetch.
// ctx is the loop context — passing it to fetchSource enables request cancellation on Close().
func (c *CloudflareChecker) fetchAll(ctx context.Context) {
	var collected []string
	for _, url := range c.cfg.Sources {
		cidrs, err := c.fetchSource(ctx, url)
		if err != nil {
			// Keep old nets on error — logged here, caller does nothing extra.
			utils.Log("CHAIN_WARN", "failed to fetch Cloudflare CIDRs from "+url+": "+err.Error(), "warning")
			continue
		}
		collected = append(collected, cidrs...)
	}
	if len(collected) == 0 {
		// No sources succeeded — keep existing nets (fallback or last successful fetch).
		// Avoid replacing a working list with an empty one.
		return
	}
	parsed := parseCIDRList(collected)
	c.mu.Lock()
	c.nets = parsed
	c.mu.Unlock()
}

// fetchSource downloads one CIDR list from url.
// ctx propagation allows the in-flight request to be cancelled when Close() is called,
// preventing a 30s hang during graceful shutdown (without ctx, client.Get waits for timeout).
// Each line is expected to be either a CIDR, a comment (prefix '#'), or blank.
func (c *CloudflareChecker) fetchSource(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &fetchError{url: url, status: resp.StatusCode}
	}

	// LimitReader prevents a rogue source from feeding us an unbounded response.
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, fetchLimitBytes))
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidrs = append(cidrs, line)
	}
	return cidrs, scanner.Err()
}

// parseCIDRList converts a slice of CIDR strings into []*net.IPNet.
// Invalid entries are silently skipped — a single bad line from a remote source
// should not prevent the rest of the list from being used.
//
// Internal — no config mapping. Consumer: NewCloudflareChecker, fetchAll.
func parseCIDRList(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue // skip malformed entries from remote sources
		}
		nets = append(nets, network)
	}
	return nets
}

// fetchError is returned when a source URL responds with a non-200 status.
type fetchError struct {
	url    string
	status int
}

func (e *fetchError) Error() string {
	return "HTTP " + http.StatusText(e.status) + " from " + e.url
}
