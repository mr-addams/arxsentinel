package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CFItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type CFClient interface {
	FindOrCreateList(ctx context.Context, name string) (listID string, err error)
	ListItems(ctx context.Context, listID string) ([]CFItem, error)
	AddItem(ctx context.Context, listID, ip, comment string) (string, error)
	AddItems(ctx context.Context, listID string, items []CFBatchItem) error
	RemoveItems(ctx context.Context, listID string, ids []string) error
	GetAllItems(ctx context.Context, listID string) ([]CFItem, error)
}

type CFBatchItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

type cfList struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type cfItem struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type HTTPCFClient struct {
	accountID  string
	token      string
	httpClient *http.Client
	baseURL    string
}

func NewHTTPCFClient(accountID, token string) *HTTPCFClient {
	return &HTTPCFClient{
		accountID: accountID,
		token:     token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.cloudflare.com/client/v4",
	}
}

func NewHTTPCFClientWithBaseURL(accountID, token, baseURL string) *HTTPCFClient {
	return &HTTPCFClient{
		accountID: accountID,
		token:     token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
	}
}

func (c *HTTPCFClient) doRequest(ctx context.Context, method, path string, body any) (*cfAPIResponse, error) {
	url := c.baseURL + path

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: marshal request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("cloudflare: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: execute request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp cfAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("cloudflare: decode response: %w", err)
	}

	if !apiResp.Success {
		if len(apiResp.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare: %s", apiResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare: request failed with no error details")
	}

	return &apiResp, nil
}

func (c *HTTPCFClient) FindOrCreateList(ctx context.Context, name string) (string, error) {
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

	createPath := fmt.Sprintf("/accounts/%s/rules/lists", c.accountID)
	createBody := map[string]string{
		"name": name,
		"kind": "ip",
	}
	apiResp, err = c.doRequest(ctx, http.MethodPost, createPath, createBody)
	if err != nil {
		return "", fmt.Errorf("cloudflare: create list %q: %w — hint: check list_name in config or free tier limits", name, err)
	}

	var created cfList
	if err := json.Unmarshal(apiResp.Result, &created); err != nil {
		return "", fmt.Errorf("cloudflare: unmarshal created list: %w", err)
	}

	return created.ID, nil
}

func (c *HTTPCFClient) ListItems(ctx context.Context, listID string) ([]CFItem, error) {
	return c.GetAllItems(ctx, listID)
}

func (c *HTTPCFClient) GetAllItems(ctx context.Context, listID string) ([]CFItem, error) {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)
	apiResp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: list items: %w", err)
	}

	var items []cfItem
	if err := json.Unmarshal(apiResp.Result, &items); err != nil {
		return nil, fmt.Errorf("cloudflare: unmarshal items: %w", err)
	}

	result := make([]CFItem, len(items))
	for i, it := range items {
		result[i] = CFItem{ID: it.ID, IP: it.IP}
	}

	return result, nil
}

func (c *HTTPCFClient) AddItem(ctx context.Context, listID, ip, comment string) (string, error) {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)
	body := []map[string]string{
		{"ip": ip, "comment": comment},
	}

	apiResp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", fmt.Errorf("cloudflare: add item: %w", err)
	}

	var items []cfItem
	if err := json.Unmarshal(apiResp.Result, &items); err != nil {
		return "", fmt.Errorf("cloudflare: add item: unmarshal result: %w", err)
	}

	if len(items) == 0 {
		return "", fmt.Errorf("cloudflare: add item: empty result")
	}

	return items[0].ID, nil
}

func (c *HTTPCFClient) AddItems(ctx context.Context, listID string, items []CFBatchItem) error {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)
	body := make([]map[string]string, len(items))
	for i, item := range items {
		body[i] = map[string]string{
			"ip":      item.IP,
			"comment": item.Comment,
		}
	}

	if _, err := c.doRequest(ctx, http.MethodPost, path, body); err != nil {
		return fmt.Errorf("cloudflare: add items: %w", err)
	}

	return nil
}

func (c *HTTPCFClient) RemoveItems(ctx context.Context, listID string, ids []string) error {
	path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", c.accountID, listID)

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
