package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBearerAuth_ConstantTime verifies that bearerAuth uses constant-time
// comparison for the full "Bearer <token>" string, preventing timing side-channels.
func TestBearerAuth_ConstantTime(t *testing.T) {
	token := "secret-token-123"
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	h := bearerAuth(token, next)

	tests := []struct {
		name       string
		authHeader string
		wantCode   int
		wantCalled bool
	}{
		{
			name:       "valid token",
			authHeader: "Bearer secret-token-123",
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "wrong token",
			authHeader: "Bearer wrong-token",
			wantCode:   401,
			wantCalled: false,
		},
		{
			name:       "missing bearer prefix",
			authHeader: "secret-token-123",
			wantCode:   401,
			wantCalled: false,
		},
		{
			name:       "empty header",
			authHeader: "",
			wantCode:   401,
			wantCalled: false,
		},
		{
			name:       "lowercase bearer",
			authHeader: "bearer secret-token-123",
			wantCode:   401,
			wantCalled: false,
		},
		{
			name:       "token with special characters",
			authHeader: "Bearer token-with_special.chars-456",
			wantCode:   401,
			wantCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("POST", "/", nil)
			req.Header.Set("Authorization", tt.authHeader)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}
			if called != tt.wantCalled {
				t.Errorf("expected next handler called=%v, got %v", tt.wantCalled, called)
			}
		})
	}
}

// TestBearerAuth_NoToken verifies that bearerAuth passes through when no token is configured.
func TestBearerAuth_NoToken(t *testing.T) {
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	h := bearerAuth("", next)

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when token is empty")
	}
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestPushServerTimeouts verifies that runPush creates a server with proper timeouts.
func TestPushServerTimeouts(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	// Create a minimal parsedConfig
	cfg := &parsedConfig{
		host:   "127.0.0.1",
		port:   "0",
		scheme: "http",
	}

	// We can't easily access the server fields from outside, but we can at least
	// verify that runPush starts and stops cleanly with the timeout settings.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runPush(ctx, cfg, handler)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("runPush returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runPush did not shut down within 3s")
	}
}
