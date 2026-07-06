// ====== Module: openwrt — client ===============================================
//   HTTP client for the OpenWrt ubus JSON-RPC 2.0 endpoint (uhttpd-mod-ubus).
//   Handles session.login, automatic re-authentication, and UCI / rc.init calls
//   used by the executor to manage an nftables ipset via UCI edits and a
//   firewall reload — see DECISIONS.md Decision 3 and Decision 4.
//
//   WHAT IS HERE:
//     Client interface, HTTPClient implementation, session lifecycle, low-level
//     JSON-RPC envelope plumbing.
//
//   WHAT IS NOT HERE:
//     Executor business logic (executor.go), config parsing (config.go),
//     registration (register.go).

package openwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// nullSession is the canonical "unauthenticated" session ID used by uhttpd-mod-ubus
// when calling session.login (and any other public method that doesn't require
// an authenticated session).
const nullSession = "00000000000000000000000000000000"

// jsonRPCRequest is the JSON-RPC 2.0 envelope for ubus calls. The Params array
// for the ubus "call" wrapper is [sessionID, object, method, args].
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// jsonRPCResponse is what uhttpd-mod-ubus returns on success. Only "result"
// is consumed — "error" responses (e.g. parse errors, unknown method) are
// surfaced by call() through the HTTP status check.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
}

// Client is the surface area of the ubus client that OpenwrtExecutor depends on.
// The concrete implementation is HTTPClient below.
type Client interface {
	Login(ctx context.Context) error
	AddEntry(ctx context.Context, ip string) error
	DeleteEntry(ctx context.Context, ip string) error
	ListEntries(ctx context.Context) ([]string, error)
	Reload(ctx context.Context) error
}

// HTTPClient implements Client over uhttpd-mod-ubus (POST /ubus, JSON-RPC 2.0).
//
// Concurrency: c.mu protects c.sessionID and c.sessionAt. All public methods
// take the lock and delegate to the *Locked helpers; call() is intentionally
// lock-free and works on the sessionID passed in by the caller.
type HTTPClient struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	sessionID  string
	sessionAt  time.Time
	reqCounter int
}

func NewHTTPClient(cfg Config) *HTTPClient {
	return &HTTPClient{cfg: cfg, httpClient: &http.Client{Timeout: 30 * time.Second}}
}

// baseURL builds scheme://host:port/ubus from cfg.
func (c *HTTPClient) baseURL() string {
	return fmt.Sprintf("%s://%s:%d/ubus", c.cfg.Scheme, c.cfg.Host, c.cfg.Port)
}

// call performs a single JSON-RPC 2.0 POST to /ubus with the given session,
// object, method and args. Returns the raw 'result' array element [1]
// (the data payload) after checking that result[0] (ubus return code) is 0.
// Does NOT touch c.mu or c.sessionID — pure HTTP+envelope plumbing.
func (c *HTTPClient) call(ctx context.Context, sessionID, object, method string, args map[string]any) (json.RawMessage, error) {
	c.reqCounter++
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      c.reqCounter,
		Method:  "call",
		Params:  []any{sessionID, object, method, args},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("openwrt: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openwrt: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openwrt: http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openwrt: http status %d for %s.%s", resp.StatusCode, object, method)
	}

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("openwrt: decode response: %w", err)
	}

	var resultArr []json.RawMessage
	if err := json.Unmarshal(rpcResp.Result, &resultArr); err != nil {
		return nil, fmt.Errorf("openwrt: decode result array: %w", err)
	}
	if len(resultArr) == 0 {
		return nil, fmt.Errorf("openwrt: ubus call %s.%s returned empty result", object, method)
	}

	var code int
	if err := json.Unmarshal(resultArr[0], &code); err != nil {
		return nil, fmt.Errorf("openwrt: decode ubus return code: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("openwrt: ubus call %s.%s failed: code %d", object, method, code)
	}

	if len(resultArr) < 2 {
		return json.RawMessage("{}"), nil
	}
	return resultArr[1], nil
}

// loginLocked performs session.login and stores the resulting ubus_rpc_session
// and the time it was obtained. Caller must hold c.mu.
func (c *HTTPClient) loginLocked(ctx context.Context) error {
	data, err := c.call(ctx, nullSession, "session", "login", map[string]any{
		"username": c.cfg.Username,
		"password": c.cfg.Password,
	})
	if err != nil {
		return fmt.Errorf("openwrt: login: %w", err)
	}
	var resp struct {
		UbusRPCSession string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("openwrt: login: decode session: %w", err)
	}
	c.sessionID = resp.UbusRPCSession
	c.sessionAt = time.Now()
	return nil
}

func (c *HTTPClient) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginLocked(ctx)
}

// ensureSessionLocked re-logs in if the session is empty or older than
// cfg.SessionTimeout. Caller must hold c.mu.
func (c *HTTPClient) ensureSessionLocked(ctx context.Context) error {
	if c.sessionID == "" || time.Since(c.sessionAt) >= c.cfg.SessionTimeout {
		return c.loginLocked(ctx)
	}
	return nil
}

// doRequest wraps call() with automatic session management: locks c.mu,
// ensures a valid session, performs the call with the cached session ID.
func (c *HTTPClient) doRequest(ctx context.Context, object, method string, args map[string]any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureSessionLocked(ctx); err != nil {
		return nil, err
	}
	return c.call(ctx, c.sessionID, object, method, args)
}

// AddEntry adds ip to the UCI ipset section named cfg.IPSetName via
// uci.add_list (adds one value to the 'entry' list option) then uci.commit.
// Document the section-lookup decision here: since 'uci' ubus object
// addresses sections by config+section-name/index (not by the ipset's
// internal 'option name' value), and the plugin does not create the
// section, cfg.IPSetName is used directly as the UCI *section name*
// (e.g. `config ipset 'blocklist'` — a named section, not an anonymous
// @ipset[N] one). This is documented as a deployment prerequisite for
// the router-side UCI config (see README, Task 3.3).
func (c *HTTPClient) AddEntry(ctx context.Context, ip string) error {
	if _, err := c.doRequest(ctx, "uci", "add_list", map[string]any{
		"config":  "firewall",
		"section": c.cfg.IPSetName,
		"option":  "entry",
		"values":  []string{ip},
	}); err != nil {
		return fmt.Errorf("openwrt: add_list %s: %w", ip, err)
	}
	if _, err := c.doRequest(ctx, "uci", "commit", map[string]any{"config": "firewall"}); err != nil {
		return fmt.Errorf("openwrt: commit: %w", err)
	}
	return nil
}

func (c *HTTPClient) DeleteEntry(ctx context.Context, ip string) error {
	if _, err := c.doRequest(ctx, "uci", "del_list", map[string]any{
		"config":  "firewall",
		"section": c.cfg.IPSetName,
		"option":  "entry",
		"values":  []string{ip},
	}); err != nil {
		return fmt.Errorf("openwrt: del_list %s: %w", ip, err)
	}
	if _, err := c.doRequest(ctx, "uci", "commit", map[string]any{"config": "firewall"}); err != nil {
		return fmt.Errorf("openwrt: commit: %w", err)
	}
	return nil
}

func (c *HTTPClient) ListEntries(ctx context.Context) ([]string, error) {
	data, err := c.doRequest(ctx, "uci", "get", map[string]any{
		"config":  "firewall",
		"section": c.cfg.IPSetName,
		"option":  "entry",
	})
	if err != nil {
		return nil, fmt.Errorf("openwrt: list entries: %w", err)
	}
	var resp struct {
		Value []string `json:"value"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("openwrt: list entries: decode: %w", err)
	}
	return resp.Value, nil
}

func (c *HTTPClient) Reload(ctx context.Context) error {
	if _, err := c.doRequest(ctx, "rc", "init", map[string]any{
		"name":   "firewall",
		"action": "reload",
	}); err != nil {
		return fmt.Errorf("openwrt: reload firewall: %w", err)
	}
	return nil
}
