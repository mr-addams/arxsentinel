// ====== Module: opnsense — client ===============================================
//   HTTP client for OPNsense firewall REST API (alias_util operations).
//   Supports: AddEntry, DeleteEntry, ListEntries on a single pre-existing alias.
//
//   WHAT IS HERE:
//     Client interface, HTTPClient implementation, request/response helpers,
//     response-parsing for the `alias_util/list` payload.
//
//   WHAT IS NOT HERE:
//     Executor business logic (executor.go, Task 4), config parsing
//     (config.go, Task 2), registration (register.go, Task 5).
//
//   API surface (verified through opnsense-expert, see DECISIONS.md
//   Decision 2):
//     POST /api/firewall/alias_util/add/{alias_name}    {"address":"1.2.3.4"}
//     POST /api/firewall/alias_util/delete/{alias_name} {"address":"1.2.3.4"}
//     GET  /api/firewall/alias_util/list/{alias_name}
//   Authentication: HTTP Basic Auth — username=cfg.APIKey, password=cfg.APISecret.
//   Success bodies: {"result":"saved"} or {"result":"ok"}.
//   Error bodies:   {"result":"failed","message":"..."}.

package opnsense

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ========================== Client interface ==========================

// Client declares the surface area of the OPNsense REST client that
// OpnsenseExecutor depends on. All operations target a single alias
// configured via Config.AliasName — the alias must be pre-declared in
// OPNsense as type Host, Network, or External (DECISIONS.md Decision 3).
type Client interface {
	// AddEntry appends an IP to the configured alias. The change is
	// applied immediately on the firewall (alias_util/add updates the
	// underlying pfctl table per-call — no filter/apply is required).
	// Returns a non-nil error if the API responds with a non-200 status
	// or a JSON body with result=="failed" (in which case the error wraps
	// the server-provided "message" field when present).
	AddEntry(ctx context.Context, ip string) error

	// DeleteEntry removes an IP from the configured alias. Same
	// immediate-apply semantics as AddEntry.
	DeleteEntry(ctx context.Context, ip string) error

	// ListEntries returns the current set of addresses contained in the
	// configured alias. See listResponse for parsing details.
	ListEntries(ctx context.Context) ([]string, error)
}

// ========================== HTTPClient ==========================

// HTTPClient implements Client over the OPNsense REST API.
//
// baseURL is the precomputed scheme+host+port prefix; the per-method
// paths are appended at call time. httpClient is configured with a 30s
// timeout (matches the mikrotik convention) and TLS verification that
// mirrors Config.TLSVerify: when TLSVerify is false, InsecureSkipVerify
// is set to true (production OPNsense ships a self-signed cert by
// default — operators frequently flip this flag).
type HTTPClient struct {
	baseURL    string
	aliasName  string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// NewHTTPClient constructs a Client ready to talk to the OPNsense REST
// API. The alias is read from cfg.AliasName; it is the caller's
// responsibility to ensure the alias exists and is of a supported type
// (Host / Network / External). The HTTP timeout is hard-coded to 30s —
// matches the mikrotik executor's choice; long enough for the small
// JSON payloads alias_util produces, short enough to surface a stuck
// firewall promptly through ctx cancellation.
func NewHTTPClient(cfg Config) *HTTPClient {
	baseURL := fmt.Sprintf("%s://%s:%d", cfg.Scheme, cfg.Host, cfg.Port)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: !cfg.TLSVerify,
	}

	return &HTTPClient{
		baseURL:   baseURL,
		aliasName: cfg.AliasName,
		apiKey:    cfg.APIKey,
		apiSecret: cfg.APISecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

// ========================== doRequest ==========================

// doRequest builds and executes an HTTP request against the OPNsense
// REST API. body, when non-nil, is JSON-marshalled and sent as the
// request body. Returns the raw response body on a 2xx status. Any
// non-2xx status produces an error that includes the status code and
// the response body (truncated by errBodyLimit) so operators can
// diagnose 4xx/5xx failures without a separate fetch.
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	url := c.baseURL + path

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("opnsense: marshal request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("opnsense: create request: %w", err)
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opnsense: execute request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("opnsense: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("opnsense: unexpected status %d: %s", resp.StatusCode, truncate(string(rawBody), errBodyLimit))
	}

	return rawBody, nil
}

// errBodyLimit caps how much of an error response body is included in
// the error string. OPNsense error bodies are short
// ({"result":"failed","message":"..."}); 512 bytes is generous and
// keeps log lines bounded.
const errBodyLimit = 512

// truncate returns at most n bytes of s, appending an ellipsis marker
// when truncation actually happened. Safe for short s (returns as-is).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// ========================== Result envelope ==========================

// resultEnvelope is the common OPNsense response shape. The endpoint
// returns {"result":"saved"} on success and {"result":"failed","message":"..."}
// on failure — both are decoded by parseResult to drive the error path
// in AddEntry / DeleteEntry.
type resultEnvelope struct {
	Result  string `json:"result"`
	Message string `json:"message,omitempty"`
}

// parseResult decodes the OPNsense alias_util JSON response. Returns
// nil on result=="saved" or result=="ok". On result=="failed" the
// returned error wraps the server-provided "message" field (when
// present) so the executor can surface the firewall-side reason to
// its logger. A response with an unrecognised result value is treated
// as an error with the raw payload — OPNsense has been known to add
// new result codes between releases; better to fail loud than silently
// no-op.
func parseResult(raw []byte) error {
	var env resultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("opnsense: decode result envelope: %w (body: %s)", err, truncate(string(raw), errBodyLimit))
	}
	switch env.Result {
	case "saved", "ok":
		return nil
	case "failed":
		if env.Message != "" {
			return fmt.Errorf("opnsense: api returned failed: %s", env.Message)
		}
		return fmt.Errorf("opnsense: api returned failed (no message)")
	default:
		return fmt.Errorf("opnsense: unexpected result %q (body: %s)", env.Result, truncate(string(raw), errBodyLimit))
	}
}

// ========================== AddEntry ==========================

// AddEntry appends ip to the configured alias. Implements Client.
func (c *HTTPClient) AddEntry(ctx context.Context, ip string) error {
	path := "/api/firewall/alias_util/add/" + url.PathEscape(c.aliasName)
	raw, err := c.doRequest(ctx, http.MethodPost, path, map[string]string{"address": ip})
	if err != nil {
		return fmt.Errorf("opnsense: add entry: %w", err)
	}
	if err := parseResult(raw); err != nil {
		return fmt.Errorf("opnsense: add entry: %w", err)
	}
	return nil
}

// ========================== DeleteEntry ==========================

// DeleteEntry removes ip from the configured alias. Implements Client.
func (c *HTTPClient) DeleteEntry(ctx context.Context, ip string) error {
	path := "/api/firewall/alias_util/delete/" + url.PathEscape(c.aliasName)
	raw, err := c.doRequest(ctx, http.MethodPost, path, map[string]string{"address": ip})
	if err != nil {
		return fmt.Errorf("opnsense: delete entry: %w", err)
	}
	if err := parseResult(raw); err != nil {
		return fmt.Errorf("opnsense: delete entry: %w", err)
	}
	return nil
}

// ========================== ListEntries ==========================

// listResponse models the OPNsense alias_util/list payload. The exact
// JSON shape of this endpoint is not formally documented (DECISIONS.md
// Decision 2 lists it as a known item); in practice OPNsense returns
// the alias' `content` field as a single newline-separated string —
// that is the format we parse. We still accept a `rows` array as a
// fallback for completeness in case a future OPNsense release switches
// to a structured representation.
//
// "content" is the dominant shape across observed OPNsense 24.x / 25.x
// releases: a string like "1.2.3.4\n5.6.7.8\n10.0.0.0/24" with each
// address on its own line (matches the OPNsense UI rendering).
type listResponse struct {
	Content string   `json:"content,omitempty"`
	Rows    []string `json:"rows,omitempty"`
}

// parseListEntries turns the raw listResponse into a []string of
// addresses. Empty content / nil rows produce an empty slice (not nil
// + error) — a freshly-created alias legitimately has no entries.
func parseListEntries(raw []byte) ([]string, error) {
	var resp listResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("opnsense: decode list response: %w", err)
	}

	// Prefer `rows` when present and non-empty — future-proofs against
	// OPNsense moving to a structured representation.
	if len(resp.Rows) > 0 {
		out := make([]string, 0, len(resp.Rows))
		for _, r := range resp.Rows {
			r = strings.TrimSpace(r)
			if r != "" {
				out = append(out, r)
			}
		}
		return out, nil
	}

	// Default: split the newline-separated `content` string.
	if resp.Content == "" {
		return []string{}, nil
	}
	lines := strings.Split(resp.Content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// ListEntries returns the current set of addresses contained in the
// configured alias. Implements Client.
func (c *HTTPClient) ListEntries(ctx context.Context) ([]string, error) {
	path := "/api/firewall/alias_util/list/" + url.PathEscape(c.aliasName)
	raw, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("opnsense: list entries: %w", err)
	}
	entries, err := parseListEntries(raw)
	if err != nil {
		return nil, fmt.Errorf("opnsense: list entries: %w", err)
	}
	return entries, nil
}
