package adapters

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nethttp "net/http"
)

// =============================================================================
// GenericAdapter — plain text
// =============================================================================

func TestGenericAdapterPlain(t *testing.T) {
	t.Run("single line", func(t *testing.T) {
		a := New("", false)
		records, err := a.Decode([]byte("hello world"))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].RawLine != "hello world" {
			t.Fatalf("expected 'hello world', got %q", records[0].RawLine)
		}
	})

	t.Run("multi line", func(t *testing.T) {
		a := New("", false)
		records, err := a.Decode([]byte("GET /api 200 1234\nPOST /login 401 56"))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
		if records[0].RawLine != "GET /api 200 1234" {
			t.Fatalf("expected first line, got %q", records[0].RawLine)
		}
		if records[1].RawLine != "POST /login 401 56" {
			t.Fatalf("expected second line, got %q", records[1].RawLine)
		}
	})

	t.Run("CRLF lines", func(t *testing.T) {
		a := New("", false)
		records, err := a.Decode([]byte("line1\r\nline2\r\nline3"))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 3 {
			t.Fatalf("expected 3 records, got %d", len(records))
		}
		if records[0].RawLine != "line1" {
			t.Fatalf("expected 'line1', got %q", records[0].RawLine)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		a := New("", false)
		records, err := a.Decode([]byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 0 {
			t.Fatalf("expected 0 records, got %d", len(records))
		}
	})

	t.Run("blank lines are skipped", func(t *testing.T) {
		a := New("", false)
		records, err := a.Decode([]byte("a\n\n\nb"))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
	})

	t.Run("WriteAck returns 200", func(t *testing.T) {
		a := New("", false)
		w := httptest.NewRecorder()
		a.WriteAck(w, nil)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

// =============================================================================
// GenericAdapter — NDJSON
// =============================================================================

func TestGenericAdapterNDJSON(t *testing.T) {
	t.Run("valid NDJSON with message field", func(t *testing.T) {
		a := New("message", true)
		body := `{"level":"INFO","message":"request processed","ts":"2026-06-03T12:00:00Z"}
{"level":"ERROR","message":"connection timeout","ts":"2026-06-03T12:00:01Z"}`
		records, err := a.Decode([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
		if records[0].RawLine != "request processed" {
			t.Fatalf("expected 'request processed', got %q", records[0].RawLine)
		}
		if records[1].RawLine != "connection timeout" {
			t.Fatalf("expected 'connection timeout', got %q", records[1].RawLine)
		}
	})

	t.Run("empty field uses whole JSON line", func(t *testing.T) {
		a := New("", true)
		records, err := a.Decode([]byte(`{"msg":"hello"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].RawLine != `{"msg":"hello"}` {
			t.Fatalf("expected JSON line, got %q", records[0].RawLine)
		}
	})

	t.Run("missing field returns whole JSON line", func(t *testing.T) {
		a := New("nonexistent", true)
		records, err := a.Decode([]byte(`{"msg":"hello"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].RawLine != `{"msg":"hello"}` {
			t.Fatalf("expected whole JSON line, got %q", records[0].RawLine)
		}
	})

	t.Run("malformed JSON line returns error", func(t *testing.T) {
		a := New("message", true)
		_, err := a.Decode([]byte(`{invalid}`))
		if err == nil {
			t.Fatal("expected error for malformed JSON")
		}
	})
}

// =============================================================================
// CloudflareAdapter
// =============================================================================

func TestCloudflareAdapterDecode(t *testing.T) {
	body := `{"EdgeStartTimestamp":1720000000000000000,"EdgeResponseBytes":1024,"ClientRequestPath":"/api","ClientIP":"203.0.113.1"}
{"EdgeStartTimestamp":1720000000001000000,"EdgeResponseBytes":512,"ClientRequestPath":"/login","ClientIP":"203.0.113.2"}`
	a := &CloudflareAdapter{}
	records, err := a.Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if !strings.Contains(records[0].RawLine, "EdgeStartTimestamp") {
		t.Fatalf("expected JSON with EdgeStartTimestamp, got %q", records[0].RawLine)
	}
	if !strings.Contains(records[1].RawLine, "ClientIP") {
		t.Fatalf("expected JSON with ClientIP, got %q", records[1].RawLine)
	}
}

func TestCloudflareAdapterWriteAck(t *testing.T) {
	a := &CloudflareAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCloudflareChallenge(t *testing.T) {
	t.Run("GET with Ownership-Challenge header returns 200 + token in body", func(t *testing.T) {
		handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			t.Fatal("next handler should not be called")
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?validate=true", nil)
		r.Header.Set("Ownership-Challenge", "my-challenge-token")
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "my-challenge-token" {
			t.Fatalf("expected 'my-challenge-token', got %q", w.Body.String())
		}
	})

	t.Run("POST without challenge header passes through", func(t *testing.T) {
		handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("passed"))
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "passed" {
			t.Fatalf("expected 'passed', got %q", w.Body.String())
		}
	})
}

// TestCloudflareChallenge_RejectsMaliciousInput verifies that challenge tokens
// containing characters outside [a-zA-Z0-9._-] are rejected with 400.
func TestCloudflareChallenge_RejectsMaliciousInput(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
	}{
		{"SQL injection", "' OR 1=1 --"},
		{"Shell injection", "$(cat /etc/passwd)"},
		{"Newline injection", "valid\nHTTP/1.1 200 OK"},
		{"HTML injection", "<script>alert(1)</script>"},
		{"Null byte", "valid\x00malicious"},
		{"Spaces", "token with spaces"},
		{"Semicolons", "abc;rm -rf /"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				t.Fatal("next handler should not be called with challenge")
			}))
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/?validate=true", nil)
			r.Header.Set("Ownership-Challenge", tt.challenge)
			handler.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("expected 400 for malicious challenge, got %d; body: %s", w.Code, w.Body.String())
			}
		})
	}

	// Empty challenge on GET /?validate=true should pass through to next handler
	// (tested separately because the table above expects 400 for all entries).
	t.Run("Empty string passes through", func(t *testing.T) {
		handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("next-handler"))
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?validate=true", nil)
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200 from next handler, got %d", w.Code)
		}
		if w.Body.String() != "next-handler" {
			t.Fatalf("expected 'next-handler', got %q", w.Body.String())
		}
	})

	// Valid challenges must still pass.
	t.Run("valid challenge passes", func(t *testing.T) {
		handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			t.Fatal("next handler should not be called")
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?validate=true", nil)
		r.Header.Set("Ownership-Challenge", "my-valid_token_123.cloudflare")
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200 for valid challenge, got %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
			t.Fatalf("expected Content-Type text/plain, got %q", ct)
		}
		if w.Body.String() != "my-valid_token_123.cloudflare" {
			t.Fatalf("expected challenge token in body, got %q", w.Body.String())
		}
	})

	// Empty challenge header on GET /?validate=true should pass through to next handler.
	t.Run("empty challenge passes through", func(t *testing.T) {
		handler := CloudflareChallengeMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("next-handler"))
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?validate=true", nil)
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200 from next handler, got %d", w.Code)
		}
		if w.Body.String() != "next-handler" {
			t.Fatalf("expected 'next-handler', got %q", w.Body.String())
		}
	})
}

// =============================================================================
// FirehoseAdapter
// =============================================================================

func TestFirehoseAdapterDecode(t *testing.T) {
	line1 := "GET /api 200 1234"
	line2 := "POST /login 401 56"
	enc1 := base64.StdEncoding.EncodeToString([]byte(line1))
	enc2 := base64.StdEncoding.EncodeToString([]byte(line2))
	payload := fmt.Sprintf(`{
		"requestId": "test-req-1",
		"timestamp": 1720000000000,
		"records": [
			{"data": "%s"},
			{"data": "%s"}
		]
	}`, enc1, enc2)

	a := &FirehoseAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].RawLine != line1 {
		t.Fatalf("expected %q, got %q", line1, records[0].RawLine)
	}
	if records[1].RawLine != line2 {
		t.Fatalf("expected %q, got %q", line2, records[1].RawLine)
	}
}

func TestFirehoseAdapterDecode_errors(t *testing.T) {
	t.Run("missing records field returns empty", func(t *testing.T) {
		a := &FirehoseAdapter{}
		records, err := a.Decode([]byte(`{"requestId":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 0 {
			t.Fatalf("expected 0 records, got %d", len(records))
		}
	})

	t.Run("invalid base64 data", func(t *testing.T) {
		a := &FirehoseAdapter{}
		payload := `{"requestId":"x","timestamp":0,"records":[{"data":"!!!invalid-base64!!!"}]}`
		_, err := a.Decode([]byte(payload))
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})
}

func TestFirehoseAdapterWriteAck(t *testing.T) {
	a := &FirehoseAdapter{}
	w := httptest.NewRecorder()
	meta := map[string]string{"X-Amz-Firehose-Request-Id": "req-001"}
	a.WriteAck(w, meta)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON response: %v", err)
	}
	if resp["requestId"] != "req-001" {
		t.Fatalf("expected requestId 'req-001', got %v", resp["requestId"])
	}
	ts, ok := resp["timestamp"].(float64)
	if !ok || ts <= 0 {
		t.Fatalf("expected positive timestamp, got %v", resp["timestamp"])
	}
}

// TestFirehoseAdapter_WriteAck_EscapesQuotes verifies that WriteAck uses
// proper JSON encoding to prevent injection via requestID with " and \.
func TestFirehoseAdapter_WriteAck_EscapesQuotes(t *testing.T) {
	a := &FirehoseAdapter{}
	w := httptest.NewRecorder()
	meta := map[string]string{"X-Amz-Firehose-Request-Id": `req"with"quotes\and\backslash`}
	a.WriteAck(w, meta)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON after injection: %v", err)
	}
	if resp["requestId"] != `req"with"quotes\and\backslash` {
		t.Fatalf("requestId round-trip failed: got %v", resp["requestId"])
	}
	// Ensure the raw body does not contain unescaped quotes that would break JSON.
	body := w.Body.String()
	if len(body) < 2 {
		t.Fatal("body too short")
	}
	// Re-parse as raw JSON to confirm structural integrity.
	var raw any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("raw body is not valid JSON: %v\nbody: %s", err, body)
	}
}

// =============================================================================
// PubSubAdapter
// =============================================================================

func TestPubSubAdapterDecode(t *testing.T) {
	logContent := "order created: 12345"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(logContent))
	payload := fmt.Sprintf(`{
		"message": {
			"data": "%s",
			"messageId": "msg-001",
			"publishTime": "2026-06-03T12:00:00.000Z",
			"attributes": {"key": "value"}
		},
		"subscription": "projects/my-project/subscriptions/my-sub"
	}`, encoded)

	a := &PubSubAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RawLine != logContent {
		t.Fatalf("expected %q, got %q", logContent, records[0].RawLine)
	}
	if records[0].Metadata["messageId"] != "msg-001" {
		t.Fatalf("expected messageId 'msg-001', got %q", records[0].Metadata["messageId"])
	}
}

func TestPubSubAdapterDecode_errors(t *testing.T) {
	t.Run("missing message.data returns empty line", func(t *testing.T) {
		a := &PubSubAdapter{}
		records, err := a.Decode([]byte(`{"message":{"messageId":"x"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].RawLine != "" {
			t.Fatalf("expected empty RawLine, got %q", records[0].RawLine)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		a := &PubSubAdapter{}
		payload := `{"message":{"data":"!!!invalid!!!","messageId":"x"}}`
		_, err := a.Decode([]byte(payload))
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})
}

func TestPubSubAdapterWriteAck(t *testing.T) {
	a := &PubSubAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

// =============================================================================
// LokiAdapter
// =============================================================================

func TestLokiAdapterDecode(t *testing.T) {
	payload := `{
		"streams": [
			{
				"stream": {"job": "nginx", "instance": "web-1"},
				"values": [
					["1720000000000000000", "GET /api 200 1234"],
					["1720000000001000000", "POST /login 401 56"]
				]
			}
		]
	}`

	a := &LokiAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].RawLine != "GET /api 200 1234" {
		t.Fatalf("expected 'GET /api 200 1234', got %q", records[0].RawLine)
	}
	if records[0].Timestamp != 1720000000000000000 {
		t.Fatalf("expected timestamp 1720000000000000000, got %d", records[0].Timestamp)
	}
	if records[0].Metadata["job"] != "nginx" {
		t.Fatalf("expected Metadata[job]='nginx', got %q", records[0].Metadata["job"])
	}
	if records[0].Metadata["instance"] != "web-1" {
		t.Fatalf("expected Metadata[instance]='web-1', got %q", records[0].Metadata["instance"])
	}

	if records[1].RawLine != "POST /login 401 56" {
		t.Fatalf("expected 'POST /login 401 56', got %q", records[1].RawLine)
	}
	if records[1].Timestamp != 1720000000001000000 {
		t.Fatalf("expected timestamp 1720000000001000000, got %d", records[1].Timestamp)
	}
}

func TestLokiAdapterDecode_multipleStreams(t *testing.T) {
	payload := `{
		"streams": [
			{
				"stream": {"job": "nginx"},
				"values": [["1720000000000000000", "line1"]]
			},
			{
				"stream": {"job": "apache"},
				"values": [["1720000000001000000", "line2"]]
			}
		]
	}`

	a := &LokiAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Metadata["job"] != "nginx" {
		t.Fatalf("expected 'nginx', got %q", records[0].Metadata["job"])
	}
	if records[1].Metadata["job"] != "apache" {
		t.Fatalf("expected 'apache', got %q", records[1].Metadata["job"])
	}
}

func TestLokiAdapterWriteAck(t *testing.T) {
	a := &LokiAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

// =============================================================================
// OTLPAdapter
// =============================================================================

func TestOTLPAdapterDecode(t *testing.T) {
	payload := `{
		"resourceLogs": [
			{
				"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "myapp"}}]},
				"scopeLogs": [
					{
						"scope": {"name": "my-logger"},
						"logRecords": [
							{
								"timeUnixNano": "1720000000000000000",
								"severityNumber": 9,
								"severityText": "INFO",
								"body": {"stringValue": "request processed"},
								"attributes": [
									{"key": "http.status_code", "value": {"intValue": 200}}
								]
							}
						]
					}
				]
			}
		]
	}`

	a := &OTLPAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RawLine != "request processed" {
		t.Fatalf("expected 'request processed', got %q", records[0].RawLine)
	}
	if records[0].Timestamp != 1720000000000000000 {
		t.Fatalf("expected timestamp 1720000000000000000, got %d", records[0].Timestamp)
	}
}

func TestOTLPAdapterDecode_bytesValue(t *testing.T) {
	logContent := "binary log content"
	encoded := base64.StdEncoding.EncodeToString([]byte(logContent))
	payload := fmt.Sprintf(`{
		"resourceLogs": [
			{
				"scopeLogs": [
					{
						"logRecords": [
							{
								"timeUnixNano": "1720000000000000000",
								"body": {"bytesValue": "%s"}
							}
						]
					}
				]
			}
		]
	}`, encoded)

	a := &OTLPAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RawLine != logContent {
		t.Fatalf("expected %q, got %q", logContent, records[0].RawLine)
	}
}

func TestOTLPAdapterDecode_attributes(t *testing.T) {
	payload := `{
		"resourceLogs": [
			{
				"scopeLogs": [
					{
						"logRecords": [
							{
								"timeUnixNano": "1720000000000000000",
								"body": {"stringValue": "test"},
								"attributes": [
									{"key": "http.status_code", "value": {"stringValue": "200"}},
									{"key": "method", "value": {"stringValue": "GET"}}
								]
							}
						]
					}
				]
			}
		]
	}`

	a := &OTLPAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Metadata["http.status_code"] != "200" {
		t.Fatalf("expected '200', got %q", records[0].Metadata["http.status_code"])
	}
	if records[0].Metadata["method"] != "GET" {
		t.Fatalf("expected 'GET', got %q", records[0].Metadata["method"])
	}
}

func TestOTLPAdapterWriteAck(t *testing.T) {
	a := &OTLPAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	if strings.TrimSpace(w.Body.String()) != `{"partialSuccess":{}}` {
		t.Fatalf("expected '{\"partialSuccess\":{}}', got %q", w.Body.String())
	}
}

// =============================================================================
// AzureAdapter
// =============================================================================

func TestAzureAdapterDecode(t *testing.T) {
	t.Run("real Azure Monitor payload", func(t *testing.T) {
		payload := `[
			{"time":"2026-06-03T12:00:00Z","level":"INFO","message":"request processed","service":"myapp","duration_ms":123},
			{"time":"2026-06-03T12:00:01Z","level":"ERROR","message":"connection timeout","service":"myapp","duration_ms":5000}
		]`

		a := &AzureAdapter{}
		records, err := a.Decode([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(records))
		}
		if !strings.Contains(records[0].RawLine, "INFO") {
			t.Fatalf("expected INFO in RawLine, got %q", records[0].RawLine)
		}
		if !strings.Contains(records[1].RawLine, "ERROR") {
			t.Fatalf("expected ERROR in RawLine, got %q", records[1].RawLine)
		}

		expectedTs, _ := time.Parse(time.RFC3339, "2026-06-03T12:00:00Z")
		if records[0].Timestamp != expectedTs.UnixNano() {
			t.Fatalf("expected %d, got %d", expectedTs.UnixNano(), records[0].Timestamp)
		}
	})

	t.Run("missing time field returns 0 timestamp", func(t *testing.T) {
		payload := `[{"message":"no timestamp here"}]`
		a := &AzureAdapter{}
		records, err := a.Decode([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Timestamp != 0 {
			t.Fatalf("expected 0 timestamp, got %d", records[0].Timestamp)
		}
	})
}

func TestAzureAdapterWriteAck(t *testing.T) {
	a := &AzureAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

// =============================================================================
// SplunkAdapter
// =============================================================================

func TestSplunkAdapterDecode(t *testing.T) {
	t.Run("event field string unwrapped", func(t *testing.T) {
		payload := `{"event":"raw log line","host":"web-1","sourcetype":"nginx:access","time":1720000000.123,"index":"main","fields":{"custom_field":"value"}}`

		a := &SplunkAdapter{}
		records, err := a.Decode([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].RawLine != `raw log line` {
			t.Fatalf("expected 'raw log line', got %q", records[0].RawLine)
		}
	})

	t.Run("time float is parsed to nanoseconds", func(t *testing.T) {
		payload := `{"event":"test","time":1720000000.123}`
		a := &SplunkAdapter{}
		records, err := a.Decode([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		expected := int64(1720000000.123 * 1e9)
		diff := records[0].Timestamp - expected
		if diff < 0 {
			diff = -diff
		}
		// float64 precision: ~1µs tolerance
		if diff > 1_000_000 {
			t.Fatalf("expected %d ±1ms, got %d", expected, records[0].Timestamp)
		}
	})

	t.Run("no time field yields 0 timestamp", func(t *testing.T) {
		payload := `{"event":"test"}`
		a := &SplunkAdapter{}
		records, err := a.Decode([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Timestamp != 0 {
			t.Fatalf("expected 0 timestamp, got %d", records[0].Timestamp)
		}
	})
}

func TestSplunkAdapterDecode_multipleEvents(t *testing.T) {
	payload := `{"event":"line1","time":1720000000.001}{"event":"line2","time":1720000000.002}`
	a := &SplunkAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if !strings.Contains(records[0].RawLine, "line1") {
		t.Fatalf("expected 'line1' in RawLine, got %q", records[0].RawLine)
	}
	if !strings.Contains(records[1].RawLine, "line2") {
		t.Fatalf("expected 'line2' in RawLine, got %q", records[1].RawLine)
	}
}

func TestSplunkAdapterDecode_eventObject(t *testing.T) {
	payload := `{"event":{"key":"value","nested":42},"time":1720000000.0}`
	a := &SplunkAdapter{}
	records, err := a.Decode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(records[0].RawLine), &obj); err != nil {
		t.Fatalf("expected RawLine to be valid JSON, got %q: %v", records[0].RawLine, err)
	}
	if obj["key"] != "value" {
		t.Fatalf("expected 'value', got %v", obj["key"])
	}
}

func TestSplunkAdapterWriteAck(t *testing.T) {
	a := &SplunkAdapter{}
	w := httptest.NewRecorder()
	a.WriteAck(w, nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON body: %v", err)
	}
	if body["text"] != "Success" {
		t.Fatalf("expected 'Success', got %v", body["text"])
	}
	code, ok := body["code"].(float64)
	if !ok || int(code) != 0 {
		t.Fatalf("expected code 0, got %v", body["code"])
	}
}

// =============================================================================
// NormalizeTimestamp
// =============================================================================

func TestNormalizeTimestamp(t *testing.T) {
	t.Run("unix_ns (int64)", func(t *testing.T) {
		ts, err := normalizeTimestamp("1720000000000000000", "unix_ns")
		if err != nil {
			t.Fatal(err)
		}
		if ts != 1720000000000000000 {
			t.Fatalf("expected 1720000000000000000, got %d", ts)
		}
	})

	t.Run("unix_ms", func(t *testing.T) {
		ts, err := normalizeTimestamp("1720000000000", "unix_ms")
		if err != nil {
			t.Fatal(err)
		}
		if ts != 1720000000000*1_000_000 {
			t.Fatalf("expected %d, got %d", 1720000000000*1_000_000, ts)
		}
	})

	t.Run("unix_ns_str (string)", func(t *testing.T) {
		ts, err := normalizeTimestamp("1720000000000000000", "unix_ns_str")
		if err != nil {
			t.Fatal(err)
		}
		if ts != 1720000000000000000 {
			t.Fatalf("expected 1720000000000000000, got %d", ts)
		}
	})

	t.Run("rfc3339", func(t *testing.T) {
		ts, err := normalizeTimestamp("2026-06-03T12:00:00Z", "rfc3339")
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := time.Parse(time.RFC3339, "2026-06-03T12:00:00Z")
		if ts != expected.UnixNano() {
			t.Fatalf("expected %d, got %d", expected.UnixNano(), ts)
		}
	})

	t.Run("unix_float", func(t *testing.T) {
		ts, err := normalizeTimestamp("1720000000.123", "unix_float")
		if err != nil {
			t.Fatal(err)
		}
		expected := int64(1720000000.123 * 1e9)
		diff := ts - expected
		if diff < 0 {
			diff = -diff
		}
		if diff > 1_000_000 {
			t.Fatalf("expected %d ±1ms, got %d", expected, ts)
		}
	})

	t.Run("unix_float overflow returns error", func(t *testing.T) {
		_, err := normalizeTimestamp("1e30", "unix_float")
		if err == nil {
			t.Fatal("expected error for overflow")
		}
	})

	t.Run("unknown kind returns error", func(t *testing.T) {
		_, err := normalizeTimestamp("123", "unknown_kind")
		if err == nil {
			t.Fatal("expected error for unknown kind")
		}
	})

	t.Run("invalid unix_ns returns error", func(t *testing.T) {
		_, err := normalizeTimestamp("not-a-number", "unix_ns")
		if err == nil {
			t.Fatal("expected error for invalid value")
		}
	})

	t.Run("negative unix_float out of range", func(t *testing.T) {
		_, err := normalizeTimestamp("-1e30", "unix_float")
		if err == nil {
			t.Fatal("expected error for underflow")
		}
	})

	t.Run("unix_float min valid", func(t *testing.T) {
		_, err := normalizeTimestamp("-9223372036.0", "unix_float")
		if err != nil {
			t.Fatalf("unexpected error for min valid: %v", err)
		}
	})
}

// ++++++++++++++++++++++++++ Fix 3: PubSubJWTMiddleware tests +++++++++++++++++++++++++++++

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func signRS256(privKey *rsa.PrivateKey, signingInput string) string {
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		panic(err)
	}
	return base64URLEncode(sig)
}

func buildJWT(privKey *rsa.PrivateKey, header, payload map[string]any) string {
	hdrJSON, _ := json.Marshal(header)
	payJSON, _ := json.Marshal(payload)
	hdrPart := base64URLEncode(hdrJSON)
	payPart := base64URLEncode(payJSON)
	sigPart := signRS256(privKey, hdrPart+"."+payPart)
	return hdrPart + "." + payPart + "." + sigPart
}

func jwkFromPubKey(kid string, pub *rsa.PublicKey) jwkKey {
	return jwkKey{
		Kid: kid,
		Kty: "RSA",
		N:   base64URLEncode(pub.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func TestPubSubJWTMiddleware(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey

	// Инвалидируем JWKS-кеш перед запуском: на 2-м прогоне `go test -count>1`
	// в том же бинаре кеш содержит ключи от предыдущего прогона с ДРУГИМ модулем
	// RSA — верификация подписи провалится → 401. t.Cleanup снимает за собой тоже.
	// Доступ к unexported jwksStore возможен потому что тесты в `package adapters`.
	jwksStore.Delete("jwks")
	t.Cleanup(func() { jwksStore.Delete("jwks") })

	// JWKS test server
	jwksServer := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		resp := jwksResponse{Keys: []jwkKey{jwkFromPubKey("test-kid-1", pubKey)}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksServer.Close()

	oldFetchURL := jwksFetchURL
	jwksFetchURL = jwksServer.URL
	defer func() { jwksFetchURL = oldFetchURL }()

	expectedAud := "https://example.com/pubsub"

	// helper: create a middleware handler with a recorder
	testMiddleware := func(token string) *httptest.ResponseRecorder {
		handler := PubSubJWTMiddleware(expectedAud, "", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		handler.ServeHTTP(w, r)
		return w
	}

	t.Run("valid JWT passes through", func(t *testing.T) {
		now := time.Now().Unix()
		token := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		w := testMiddleware(token)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "ok" {
			t.Fatalf("expected 'ok', got %q", w.Body.String())
		}
	})

	t.Run("wrong alg (HS256) returns 401", func(t *testing.T) {
		now := time.Now().Unix()
		token := buildJWT(privKey, map[string]any{"alg": "HS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		w := testMiddleware(token)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("expired token returns 401", func(t *testing.T) {
		token := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            time.Now().Unix() - 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		w := testMiddleware(token)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("email_verified=false returns 401", func(t *testing.T) {
		now := time.Now().Unix()
		token := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": false,
		})
		w := testMiddleware(token)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("bad signature (wrong key) returns 401", func(t *testing.T) {
		wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		now := time.Now().Unix()
		token := buildJWT(wrongKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		w := testMiddleware(token)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("malformed token (not 3 parts) returns 401", func(t *testing.T) {
		w := testMiddleware("only.two.parts.extra")
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("empty Authorization header returns 401", func(t *testing.T) {
		handler := PubSubJWTMiddleware(expectedAud, "", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		// no Authorization header at all
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("empty Authorization header variant", func(t *testing.T) {
		handler := PubSubJWTMiddleware(expectedAud, "", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "")
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("unknown kid returns 401", func(t *testing.T) {
		now := time.Now().Unix()
		token := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "unknown-kid"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		w := testMiddleware(token)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("static token + valid JWT passes through", func(t *testing.T) {
		now := time.Now().Unix()
		jwt := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            expectedAud,
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		// Static expectedToken equals the JWT — both the token gate and JWT validation pass.
		handler := PubSubJWTMiddleware(expectedAud, jwt, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+jwt)
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "ok" {
			t.Fatalf("expected 'ok', got %q", w.Body.String())
		}
	})

	t.Run("wrong static token returns 401 before JWKS fetch", func(t *testing.T) {
		jwksStore.Delete("jwks")
		handler := PubSubJWTMiddleware(expectedAud, "s3cret", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		// Wrong static token — must fail before JWKS fetch (jwksStore is empty)
		r.Header.Set("Authorization", "Bearer wrong")
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("static token + mismatched aud returns 401", func(t *testing.T) {
		now := time.Now().Unix()
		jwt := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "test-kid-1"}, map[string]any{
			"aud":            "https://wrong.example.com",
			"exp":            now + 3600,
			"email":          "user@example.com",
			"email_verified": true,
		})
		// Static token matches the JWT, but the JWT audience is wrong — fails at JWT validation.
		handler := PubSubJWTMiddleware(expectedAud, jwt, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+jwt)
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestPubSubJWTMiddleware_closesBody(t *testing.T) {
	// Снимаем кеш JWKS — иначе на 2-м прогоне `go test -count>1` будет
	// использован ключ из предыдущего прогона и верификация провалится.
	jwksStore.Delete("jwks")
	t.Cleanup(func() { jwksStore.Delete("jwks") })

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &privKey.PublicKey

	jwksServer := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		resp := jwksResponse{Keys: []jwkKey{jwkFromPubKey("kid-1", pubKey)}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksServer.Close()

	oldFetchURL := jwksFetchURL
	jwksFetchURL = jwksServer.URL
	defer func() { jwksFetchURL = oldFetchURL }()

	now := time.Now().Unix()
	token := buildJWT(privKey, map[string]any{"alg": "RS256", "kid": "kid-1"}, map[string]any{
		"aud":            "https://example.com/sub",
		"exp":            now + 3600,
		"email":          "user@example.com",
		"email_verified": true,
	})

	handler := PubSubJWTMiddleware("https://example.com/sub", "", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		if n != 2 {
			t.Errorf("expected 2 body bytes, got %d", n)
		}
		w.WriteHeader(200)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
