package mikrotik

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// AddressListEntry represents a MikroTik address-list entry.
// The .id field is empty on creation and populated by the API on response.
type AddressListEntry struct {
	ID       string `json:".id,omitempty"`
	Address  string `json:"address"`
	List     string `json:"list"`
	Timeout  string `json:"timeout,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Disabled string `json:"disabled,omitempty"`
}

// Client defines the interface for MikroTik RouterOS firewall address-list operations.
type Client interface {
	Add(ctx context.Context, entry AddressListEntry) (id string, err error)
	List(ctx context.Context, listName string) ([]AddressListEntry, error)
	Delete(ctx context.Context, id string) error
}

// HTTPClient implements Client over MikroTik RouterOS REST API.
type HTTPClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTPClient for MikroTik RouterOS REST API.
// useTLS=false switches to plain HTTP — only for local mock servers in integration tests;
// production RouterOS devices always require HTTPS.
// caFile, if non-empty, loads a PEM-encoded CA cert to verify the RouterOS TLS certificate.
// Ignored when tlsVerify is false (InsecureSkipVerify takes precedence).
func NewHTTPClient(host string, port int, username, password string, tlsVerify bool, caFile string, useTLS bool) Client {
	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s:%d/rest", scheme, host, port)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: !tlsVerify,
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			_ = err
		} else {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
			tlsCfg.RootCAs = pool
		}
	}

	return &HTTPClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	url := c.baseURL + path

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("mikrotik: marshal request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("mikrotik: create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mikrotik: execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mikrotik: unexpected status %d", resp.StatusCode)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("mikrotik: decode response: %w", err)
	}

	return []byte(raw), nil
}

// Add creates a new address-list entry via PUT /rest/ip/firewall/address-list.
// Returns the .id assigned by RouterOS.
func (c *HTTPClient) Add(ctx context.Context, entry AddressListEntry) (string, error) {
	path := "/ip/firewall/address-list"
	data, err := c.doRequest(ctx, http.MethodPut, path, entry)
	if err != nil {
		return "", fmt.Errorf("mikrotik: add address-list entry: %w", err)
	}

	var created AddressListEntry
	if err := json.Unmarshal(data, &created); err != nil {
		return "", fmt.Errorf("mikrotik: add address-list: unmarshal result: %w", err)
	}

	return created.ID, nil
}

// List returns all entries in the specified address-list via GET.
func (c *HTTPClient) List(ctx context.Context, listName string) ([]AddressListEntry, error) {
	path := fmt.Sprintf("/ip/firewall/address-list?list=%s", listName)
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("mikrotik: list address-list: %w", err)
	}

	var entries []AddressListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("mikrotik: list address-list: unmarshal: %w", err)
	}

	return entries, nil
}

// Delete removes an address-list entry by its .id via DELETE.
func (c *HTTPClient) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/ip/firewall/address-list/%s", id)
	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("mikrotik: delete address-list entry: %w", err)
	}
	return nil
}

// durationToRouterOS converts a Go duration to RouterOS timeout string format.
// Returns "" for permanent (zero duration).
// Format: only non-zero components — "1d12h30m", "30m", "7d".
func durationToRouterOS(d time.Duration) string {
	if d == 0 {
		return ""
	}

	totalSec := int64(d.Seconds())

	days := totalSec / 86400
	totalSec %= 86400

	hours := totalSec / 3600
	totalSec %= 3600

	minutes := totalSec / 60
	seconds := totalSec % 60

	var buf []byte

	if days > 0 {
		buf = strconv.AppendInt(buf, days, 10)
		buf = append(buf, 'd')
	}
	if hours > 0 {
		buf = strconv.AppendInt(buf, hours, 10)
		buf = append(buf, 'h')
	}
	if minutes > 0 {
		buf = strconv.AppendInt(buf, minutes, 10)
		buf = append(buf, 'm')
	}
	if seconds > 0 {
		buf = strconv.AppendInt(buf, seconds, 10)
		buf = append(buf, 's')
	}

	return string(buf)
}