//go:build integration

// ========================== Distributed NCS mixed-routing test (Flow 093) ================
//   A second 5-node topology, distinct from distributed_ncs_five_node_test.go's
//   aggregation-focused one: two collectors feed TWO SEPARATE detector pipelines,
//   each routing its scored verdicts to a DIFFERENT executor TYPE on a different
//   node — nginx (local blocklist file) and mikrotik (RouterOS REST API address-list,
//   mocked via httptest in this test process). This is the "mixed routing" pattern:
//   the same detector process makes two independent forwarding decisions based on
//   which pipeline scored the event, not a single fan-out to every downstream node.
//
//   Topology:
//
//     collector-web  ──▶ "edge-web"  ──▶ detector pipeline "web"  ──▶ "scored-web"  ──▶ nginx-executor    ──▶ blocklist.conf
//     collector-auth ──▶ "edge-auth" ──▶ detector pipeline "auth" ──▶ "scored-auth" ──▶ mikrotik-executor ──▶ RouterOS mock (httptest)
//
//   Both collector→detector legs use raw_forward exactly like the aggregation test;
//   the difference here is entirely on the detector→executor side: two pipelines,
//   two queue_names, two peers, two executor plugin types.
//
//   Run: go test -tags integration -run TestDistributedNCS_MixedRouting -v ./cmd/arxsentinel/
//
//   Reuses buildArxsentinelBinary / startNode / stopNodeAndAssertClean /
//   waitForFileContains / appendLine / accessLogLine / freeUDPPort from
//   distributed_ncs_integration_test.go (same package, same build tag).

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// mikrotikMock is a minimal RouterOS REST API stand-in: GET the address-list
// returns whatever has been PUT so far (empty on first call, matching a fresh
// RouterOS device with no pre-existing entries), PUT records the banned
// address. Good enough for the mikrotik executor's syncExisting + flush
// cycle — it does not need DELETE/sweep for this test.
type mikrotikMock struct {
	mu      sync.Mutex
	entries []string // IPs banned via PUT, in arrival order
}

func (m *mikrotikMock) bannedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.entries...)
}

func (m *mikrotikMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]")) // no pre-existing entries — keeps syncExisting trivial
		case http.MethodPut:
			var entry struct {
				Address string `json:"address"`
			}
			_ = json.NewDecoder(r.Body).Decode(&entry)
			_ = r.Body.Close()
			m.mu.Lock()
			m.entries = append(m.entries, entry.Address)
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{".id":"*1"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}
}

func TestDistributedNCS_MixedRouting(t *testing.T) {
	bin := buildArxsentinelBinary(t)

	// ── RouterOS mock — lives in THIS test process; the mikrotik-executor
	// subprocess reaches it over a real loopback TCP connection, exactly as it
	// would reach a real RouterOS device.
	mock := &mikrotikMock{}
	mockSrv := httptest.NewServer(mock.handler())
	defer mockSrv.Close()
	mockURL, err := url.Parse(mockSrv.URL)
	if err != nil {
		t.Fatalf("parse mock server URL %q: %v", mockSrv.URL, err)
	}
	mockHost, mockPortStr, err := net.SplitHostPort(mockURL.Host)
	if err != nil {
		t.Fatalf("split mock server host:port %q: %v", mockURL.Host, err)
	}
	mockPort, err := strconv.Atoi(mockPortStr)
	if err != nil {
		t.Fatalf("parse mock server port %q: %v", mockPortStr, err)
	}

	detectorDir := t.TempDir()
	nginxExecDir := t.TempDir()
	mikrotikExecDir := t.TempDir()
	webCollectorDir := t.TempDir()
	authCollectorDir := t.TempDir()

	detectorPort := freeUDPPort(t)
	nginxExecPort := freeUDPPort(t)
	mikrotikExecPort := freeUDPPort(t)
	webCollectorPort := freeUDPPort(t)
	authCollectorPort := freeUDPPort(t)

	blocklistPath := filepath.Join(nginxExecDir, "blocklist.conf")
	nginxIdleLog := filepath.Join(nginxExecDir, "idle.log")
	mikrotikIdleLog := filepath.Join(mikrotikExecDir, "idle.log")
	for _, p := range []string{nginxIdleLog, mikrotikIdleLog} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
	}

	// ── nginx-executor node: consumes "scored-web" from the detector's web
	// pipeline, writes a plain blocklist file. No external dependency.
	nginxExecConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
streams:
  - name: idle
    pipelines:
      - name: idle
        inputs:
          - type: file
            path: %[4]s
        outputs:
          - type: file
            path: %[1]s/idle-out.log
            format: fail2ban
executors:
  - name: block-web
    type: nginx
    sources:
      - name: scored-web
        queue:
          type: transport
          mode: recv
    config:
      list_file: %[3]s
      file_format: deny
      min_level: WARN
      batch_size: 1
      flush_interval: 200ms
      reload_cmd: ""
`, nginxExecDir, nginxExecPort, blocklistPath, nginxIdleLog)

	// ── mikrotik-executor node: consumes "scored-auth" from the detector's
	// auth pipeline, calls the RouterOS mock over plain HTTP (use_tls: false —
	// documented in Config as the local-mock-server escape hatch).
	mikrotikExecConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
streams:
  - name: idle
    pipelines:
      - name: idle
        inputs:
          - type: file
            path: %[4]s
        outputs:
          - type: file
            path: %[1]s/idle-out.log
            format: fail2ban
executors:
  - name: block-auth
    type: mikrotik
    sources:
      - name: scored-auth
        queue:
          type: transport
          mode: recv
    config:
      host: %[5]s
      port: %[6]d
      use_tls: false
      username: admin
      password: test-password
      list_name: arxsentinel
      sentinel_id: mixed-routing-test
      min_level: WARN
      batch_size: 1
      flush_interval: 200ms
      ttl: 1h
`, mikrotikExecDir, mikrotikExecPort, "_", mikrotikIdleLog, mockHost, mockPort)

	// ── Detector node — two independent pipelines under one stream. Each
	// pipeline receives from its own collector's queue_name and forwards to
	// its own executor's queue_name/peer — the mixed-routing decision is
	// simply "which pipeline scored this", made at config time, not at
	// runtime per-event.
	detectorConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
  peers:
    - host: 127.0.0.1:%[3]d
    - host: 127.0.0.1:%[4]d
streams:
  - name: detector
    pipelines:
      - name: web
        inputs:
          - type: sentinel
            addr: ncs://edge-web
            mode: raw
            queue:
              type: transport
              mode: recv
        outputs:
          - type: sentinel-threat
            name: scored-web
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
      - name: auth
        inputs:
          - type: sentinel
            addr: ncs://edge-auth
            mode: raw
            queue:
              type: transport
              mode: recv
        outputs:
          - type: sentinel-threat
            name: scored-auth
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[4]d
`, detectorDir, detectorPort, nginxExecPort, mikrotikExecPort)

	// ── Collector nodes — one feeds "edge-web", the other feeds "edge-auth".
	webLogPath := filepath.Join(webCollectorDir, "access.log")
	authLogPath := filepath.Join(authCollectorDir, "access.log")
	for _, p := range []string{webLogPath, authLogPath} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
	}
	webCollectorConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
  tail_retry_interval: 200ms
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
  peers:
    - host: 127.0.0.1:%[3]d
streams:
  - name: collector-web
    pipelines:
      - name: raw
        raw_forward: true
        inputs:
          - type: file
            path: %[4]s
        outputs:
          - type: sentinel-threat
            name: edge-web
            format: raw-line
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
`, webCollectorDir, webCollectorPort, detectorPort, webLogPath)

	authCollectorConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
  tail_retry_interval: 200ms
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
  peers:
    - host: 127.0.0.1:%[3]d
streams:
  - name: collector-auth
    pipelines:
      - name: raw
        raw_forward: true
        inputs:
          - type: file
            path: %[4]s
        outputs:
          - type: sentinel-threat
            name: edge-auth
            format: raw-line
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
`, authCollectorDir, authCollectorPort, detectorPort, authLogPath)

	paths := map[string]string{
		filepath.Join(nginxExecDir, "config.yaml"):     nginxExecConfig,
		filepath.Join(mikrotikExecDir, "config.yaml"):  mikrotikExecConfig,
		filepath.Join(detectorDir, "config.yaml"):      detectorConfig,
		filepath.Join(webCollectorDir, "config.yaml"):  webCollectorConfig,
		filepath.Join(authCollectorDir, "config.yaml"): authCollectorConfig,
	}
	for path, content := range paths {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	// ── Start order: both executors first (pure receivers), then the
	// detector (dials both executors, accepts from both collectors), then
	// both collectors last.
	cmdNginx, outNginx := startNode(t, bin, filepath.Join(nginxExecDir, "config.yaml"))
	t.Cleanup(func() { stopNodeAndAssertClean(t, "nginx-executor", cmdNginx, outNginx) })

	cmdMikrotik, outMikrotik := startNode(t, bin, filepath.Join(mikrotikExecDir, "config.yaml"))
	t.Cleanup(func() { stopNodeAndAssertClean(t, "mikrotik-executor", cmdMikrotik, outMikrotik) })
	time.Sleep(300 * time.Millisecond)

	cmdDetector, outDetector := startNode(t, bin, filepath.Join(detectorDir, "config.yaml"))
	t.Cleanup(func() { stopNodeAndAssertClean(t, "detector", cmdDetector, outDetector) })
	time.Sleep(300 * time.Millisecond)

	cmdWeb, outWeb := startNode(t, bin, filepath.Join(webCollectorDir, "config.yaml"))
	t.Cleanup(func() { stopNodeAndAssertClean(t, "collector-web", cmdWeb, outWeb) })

	cmdAuth, outAuth := startNode(t, bin, filepath.Join(authCollectorDir, "config.yaml"))
	t.Cleanup(func() { stopNodeAndAssertClean(t, "collector-auth", cmdAuth, outAuth) })

	// ── Drive traffic through each collector and verify it reaches its OWN
	// executor — and, just as importantly, does NOT show up on the other one.
	const webIP = "203.0.113.21"
	const authIP = "203.0.113.22"
	webProbe := accessLogLine(webIP, "GET", "/wp-login.php", "curl/7.88")
	authProbe := accessLogLine(authIP, "GET", "/wp-login.php", "curl/7.88")

	var blocklistHasWebIP bool
	for i := 0; i < 20 && !blocklistHasWebIP; i++ {
		appendLine(t, webLogPath, webProbe)
		_, blocklistHasWebIP = waitForFileContains(t, blocklistPath, webIP, 1*time.Second)
	}
	if !blocklistHasWebIP {
		content, _ := os.ReadFile(blocklistPath)
		t.Fatalf("blocklist.conf never contained web collector's IP %q after 20 attempts.\nblocklist.conf: %q\n--- detector ---\n%s\n--- nginx-executor ---\n%s",
			webIP, string(content), outDetector(), outNginx())
	}

	var mikrotikHasAuthIP bool
	for i := 0; i < 20 && !mikrotikHasAuthIP; i++ {
		appendLine(t, authLogPath, authProbe)
		for _, ip := range mock.bannedIPs() {
			if ip == authIP {
				mikrotikHasAuthIP = true
				break
			}
		}
		if mikrotikHasAuthIP {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !mikrotikHasAuthIP {
		t.Fatalf("RouterOS mock never received a PUT for auth collector's IP %q after 20 attempts.\nbanned so far: %v\n--- detector ---\n%s\n--- mikrotik-executor ---\n%s",
			authIP, mock.bannedIPs(), outDetector(), outMikrotik())
	}

	// ── Cross-checks: mixed routing means each IP reaches ONLY its intended
	// executor, not both — proof the two pipelines' forwarding decisions are
	// actually independent, not a fan-out that happens to look selective.
	blocklistContent, err := os.ReadFile(blocklistPath)
	if err != nil {
		t.Fatalf("read blocklist.conf: %v", err)
	}
	if strings.Contains(string(blocklistContent), authIP) {
		t.Errorf("blocklist.conf (nginx-executor) unexpectedly contains auth collector's IP %q — mixed routing leaked across pipelines", authIP)
	}
	for _, ip := range mock.bannedIPs() {
		if ip == webIP {
			t.Errorf("RouterOS mock (mikrotik-executor) unexpectedly banned web collector's IP %q — mixed routing leaked across pipelines", webIP)
		}
	}
}
