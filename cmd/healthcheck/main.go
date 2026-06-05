// ========================== Healthcheck — TCP + HTTP probe ============================
//   Tiny healthcheck binary for distroless Docker images (no curl or shell).
//   Checks: TCP connect to localhost:9117 + HTTP GET /health → {"status":"ok"}.
//
//   Built alongside arxsentinel in the Dockerfile multi-stage build.
//   Exit code 0 = healthy, 1 = unhealthy.
//
// =========================================================================================

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// targetAddr — the metrics server address exposed by arxsentinel.
// Hardcoded: healthcheck is a tiny probe that has no config file.
// In the Docker setup, the arxsentinel container binds to localhost:9117
// and the healthcheck sidecar runs in the same container via ENTRYPOINT [],
// so the address is always localhost:9117.
const (
	targetAddr = "localhost:9117"
	timeout    = 3 * time.Second
)

// main runs the two-stage healthcheck: TCP connect + HTTP /health.
// Exits 0 on success, 1 on any failure.
// Non-blocking: timeout applies to both stages independently.
func main() {
	// ── Step 1: TCP dial ──────────────────────────────────────────────────────────────
	// Verify the arxsentinel process is listening. A closed port means the
	// process either crashed or is still starting — both require a probe restart.
	// conn.Close() is safe immediately: we only needed to confirm reachability.
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TCP dial to %s failed: %v\n", targetAddr, err)
		os.Exit(1)
	}
	_ = conn.Close()

	// ── Step 2: HTTP GET /health ──────────────────────────────────────────────────────
	// Confirms the HTTP server is responding with the expected JSON payload.
	// Status code + exact body match guards against a placeholder endpoint
	// that returns 200 with wrong content (e.g. reverse proxy returning 503).
	client := http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + targetAddr + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP GET /health failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload := strings.TrimSpace(string(body))

	// Strict equality: not 200+something and not {"status":"ok "} with trailing space.
	// The /health endpoint in main.go always writes {"status":"ok"} without trailing newlines.
	if resp.StatusCode != http.StatusOK || payload != `{"status":"ok"}` {
		fmt.Fprintf(os.Stderr, "HTTP /health: status=%d body=%q\n", resp.StatusCode, payload)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "healthcheck: OK (TCP %s + HTTP /health)\n", targetAddr)
}
