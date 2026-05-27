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

const (
	targetAddr = "localhost:9117"
	timeout    = 3 * time.Second
)

func main() {
	// ── Step 1: TCP dial ──────────────────────────────────────────────────────────────
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TCP dial to %s failed: %v\n", targetAddr, err)
	}
	if conn != nil {
		_ = conn.Close()
	}

	// ── Step 2: HTTP GET /health ──────────────────────────────────────────────────────
	client := http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + targetAddr + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP GET /health failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload := strings.TrimSpace(string(body))

	if resp.StatusCode != http.StatusOK || payload != `{"status":"ok"}` {
		fmt.Fprintf(os.Stderr, "HTTP /health: status=%d body=%q\n", resp.StatusCode, payload)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "healthcheck: OK (TCP %s + HTTP /health)\n", targetAddr)
}
