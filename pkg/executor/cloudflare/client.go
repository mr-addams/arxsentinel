// ========================== Package cloudflare ==========================
//   HTTP client for Cloudflare Lists API v4.
//
//   WHAT IS HERE:
//     - CFClient interface — contract for list operations
//     - HTTPCFClient — production REST client
//     - CFItem — a single IP list entry
//
//   WHAT IS NOT HERE:
//     - Config parsing (see config.go)
//     - Mock / test double for CFClient

package cloudflare

import (
	// ── Standard library ──────────────────────────────────────────────────
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ========================== Public types ==========================

// CFItem represents a single IP entry in a Cloudflare IP List.
type CFItem struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

// CFClient is the contract for Cloudflare Lists API operations.
// Consumers define the interface; this package provides the production implementation.
type CFClient interface {
	FindOrCreateList(ctx context.Context, name string) (listID string, err error)
	ListItems(ctx context.Context, listID string) ([]CFItem, error)
	AddItem(ctx context.Context, listID, ip, comment string) (string, error)
	RemoveItems(ctx context.Context, listID string, ids []string) error
}

// ++++++++++++++++++++++++++ Private API types +++++++++++++++++++++++++++++

// cfList mirrors the Cloudflare list object returned by the API.
// Used internally to unmarshal list metadata from GET/POST responses.
type cfList struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// cfItem mirrors a single item inside a Cloudflare list response.
// Keep separate from CFItem to decouple the wire format from the public type.
type cfItem struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

// cfAPIResponse wraps the standard Cloudflare API v4 envelope.
// Every endpoint returns this structure; Success must be true for the call to be considered successful.
type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// cfAPIError carries a single error returned by the Cloudflare API.
type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ========================== Production client ==========================

// HTTPCFClient is the production implementation of CFClient backed by real HTTP calls.
//
// All four fields are unexported to force construction via NewHTTPCFClient,
// which provides sensible defaults for the HTTP client and base URL.
type HTTPCFClient struct {
	accountID  string       // Cloudflare account identifier used in all API paths
	token      string       // API token with Lists:Edit permission
	httpClient *http.Client // HTTP client with 30 s timeout (configurable via constructor in the future)
	baseURL    string       // Always "https://api.cloudflare.com/client/v4"
}

// NewHTTPCFClient creates a production CFClient backed by real HTTP requests.
//
// accountID is the 32-hex-char Cloudflare account tag; token is an API token
// that has at least the "IP Lists: Edit" permission for the given account.
// The returned client is safe for concurrent use because http.Client is itself
// safe and the struct carries no mutable shared state.
func NewHTTPCFClient(accountID, token string) *HTTPCFClient {
	return &HTTPCFClient{
		accountID: accountID,
		token:     token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // Safety net — no request should hang indefinitely
		},
		baseURL: "https://api.cloudflare.com/client/v4",
	}
}

// ++++++++++++++++++++++++++ Internal helpers +++++++++++++++++++++++++++++

// doRequest sends an authenticated HTTP request to the Cloudflare API and decodes the response.
//
// body, when non-nil, is marshalled to JSON and sent as the request payload.
// The Content-Type header is only set when a body is present — GET and DELETE requests
// without a body omit it entirely.
//
// Returns a parsed cfAPIResponse only when the HTTP round-trip and JSON decoding succeed.
// Application-level errors (Success == false) are converted to Go errors using the first
// API error message.
func (c *HTTPCFClient) doRequest(ctx context.Context, method, path string, body any) (*cfAPIResponse, error) {
	url := c.baseURL + path

	// ── Marshal body (if any) ──────────────────────────────────────────────
	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: marshal request body: %w", err)
		}
	}

	// ── Build request ──────────────────────────────────────────────────────
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("cloudflare: create request: %w", err)
	}

	// ── Headers ────────────────────────────────────────────────────────────
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// ── Execute ────────────────────────────────────────────────────────────
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: execute request: %w", err)
	}
	defer resp.Body.Close()

	// ── Decode ─────────────────────────────────────────────────────────────
	var apiResp cfAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("cloudflare: decode response: %w", err)
	}

	// ── Check for API-level errors ─────────────────────────────────────────
	if !apiResp.Success {
		if len(apiResp.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare: %s", apiResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare: request failed with no error details")
	}

	return &apiResp, nil
}

// ========================== CFClient implementation ==========================

// FindOrCreateList resolves a list name to its Cloudflare ID, creating the list
// if it does not already exist.
//
// The lookup-then-create approach avoids unconditional creation so that repeated
// invocations are idempotent — the list is only created once.
func (c *HTTPCFClient) FindOrCreateList(ctx context.Context, name string) (string, error) {
	// ── Step 1: try to find an existing list by name ───────────────────────
	path := fmt.Sprintf("/accounts/%s/rules/lists", c.accountID)
	apiResp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("cloudflare: list lists: %w", err)
	}

	var lists []cfList
	if err := json.Unmarshal(apiResp.Result, &lists); err != nil {
		return "", fmt.Errorf("cloudflare: unmarshal lists: %w", err)
	}

	for _, l := range lists {
		if l.Name == name {
			return l.ID, nil
		}
	}

	// ── Step 2: not found — create it ──────────────────────────────────────
	createPath := fmt.Sprintf("/accounts/%s/rules/lists", c.accountID)
	createBody := map[string]string{
		"name": name,
		"kind": "ip",
	}
	apiResp, err = c.doRequest(ctx, http.MethodPost, createPath, createBody)
	if err != nil {
		// Decision 9: provide a hint about the config when creation fails.
		// The most common causes are a wrong list_name spelling or free-plan
		// limits (max 10 lists).
		return "", fmt.Errorf("cloudflare: create list %q: %w — hint: check list_name in config or free tier limits", name, err)
	}

	var created cfList
	if err := json.Unmarshal(apiResp.Result, &created); err != nil {
		return "", fmt.Errorf("cloudflare: unmarshal created list: %w", err)
	}

	return created.ID, nil
}

// ListItems returns every IP entry currently in the given Cloudflare list.
//
// The API returns items in no guaranteed order; the caller should sort if needed.
func (c *HTTPCFClient) ListItems(ctx context.Context, listID string) ([]CFItem, error) {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)
	apiResp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: list items: %w", err)
	}

	var items []cfItem
	if err := json.Unmarshal(apiResp.Result, &items); err != nil {
		return nil, fmt.Errorf("cloudflare: unmarshal items: %w", err)
	}

	// Map wire format to public type — keeps CFItem decoupled from cfItem.
	result := make([]CFItem, len(items))
	for i, it := range items {
		result[i] = CFItem{ID: it.ID, IP: it.IP}
	}

	return result, nil
}

// AddItem appends a single IP to the specified Cloudflare list.
//
// comment is a human-readable label visible in the Cloudflare dashboard.
// Empty comments are accepted by the API but discouraged for auditability.
//
// Returns the Cloudflare-assigned item ID on success, which is used by the
// executor to update the local banRecord's cfItemID immediately (S-02).
func (c *HTTPCFClient) AddItem(ctx context.Context, listID, ip, comment string) (string, error) {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)

	// The Cloudflare bulk-items endpoint expects an array even for single inserts.
	body := []map[string]string{
		{
			"ip":      ip,
			"comment": comment,
		},
	}

	apiResp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", fmt.Errorf("cloudflare: add item: %w", err)
	}

	// Parse the response to extract the created item's ID.
	// The Cloudflare API returns an array of created items in the result field.
	var items []cfItem
	if err := json.Unmarshal(apiResp.Result, &items); err != nil {
		return "", fmt.Errorf("cloudflare: add item: unmarshal result: %w", err)
	}

	if len(items) == 0 {
		return "", fmt.Errorf("cloudflare: add item: empty result")
	}

	return items[0].ID, nil
}

// RemoveItems deletes multiple entries from a Cloudflare list by their item IDs.
//
// ids must contain the Cloudflare-assigned item identifiers (obtained from ListItems).
// This is a bulk operation — either all items are removed or the entire request fails.
func (c *HTTPCFClient) RemoveItems(ctx context.Context, listID string, ids []string) error {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)

	// The API expects: { "items": [ { "id": "..." }, ... ] }
	type removeItem struct {
		ID string `json:"id"`
	}
	items := make([]removeItem, len(ids))
	for i, id := range ids {
		items[i] = removeItem{ID: id}
	}

	body := map[string]any{
		"items": items,
	}

	if _, err := c.doRequest(ctx, http.MethodDelete, path, body); err != nil {
		return fmt.Errorf("cloudflare: remove items: %w", err)
	}

	return nil
}
