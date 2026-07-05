//go:build integration

// ========================== Distributed NCS 5-node integration test (Flow 093) ===========
//   Extends the 2-node acceptance test (distributed_ncs_integration_test.go) to a
//   5-node topology exercising THREE distinct distributed-processing patterns in one
//   run, matching the original brief this whole feature was built for: heterogeneous
//   collection + aggregation, routing between nodes, and processing split across
//   different nodes.
//
//   Topology:
//
//     collector-1 ─┐
//     collector-2 ─┼──▶ "edge-raw" (transport, mode=send/recv) ──▶  detector
//     collector-3 ─┘                                                   │
//                                                                      │ scores for real
//                                                                      ▼
//                                                    "scored-events" (transport, send/recv)
//                                                                      │
//                                                                      ▼
//                                                             executor node
//                                                          (nginx blocklist
//                                                           executor plugin)
//                                                                      │
//                                                                      ▼
//                                                             blocklist.conf
//
//   - AGGREGATION: three independent collector nodes (simulating heterogeneous
//     sources — nginx access log, an API log, an auth log — each with its own
//     transport identity) all raw_forward onto the SAME queue_name "edge-raw" on
//     the detector. One registered inbound handler on the detector's side receives
//     frames from all three senders — proof that Distributed NCS's fan-in is a
//     property of the receiving side's single registration, not of how many remote
//     peers dial in.
//   - ROUTING: the detector does not write locally at all — its sink forwards
//     SCORED events under a DIFFERENT queue_name ("scored-events") to a fifth node.
//   - DISTRIBUTED PROCESSING: parsing happens on the collectors, scoring happens
//     on the detector, and the final response happens on a fifth node — via a
//     REAL executor plugin (nginx blocklist), the correct consumer for a
//     sentinel-threat sink's opaque ThreatEvent JSON (an ordinary stream
//     pipeline would panic on UnwrapLogEntry — see mode: raw's doc comment in
//     pkg/source/sentinel). Three different responsibilities, three processes.
//
//   Run: go test -tags integration -run TestDistributedNCS_FiveNode -v ./cmd/arxsentinel/
//
//   Reuses buildArxsentinelBinary / startNode / stopNodeAndAssertClean /
//   waitForFileContains / appendLine / accessLogLine / freeUDPPort from
//   distributed_ncs_integration_test.go (same package, same build tag).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fiveNodeCollector describes one collector node's identity, port, and the
// probe IP it will send — kept as a slice so the aggregation loop below is
// data-driven rather than three near-identical copy-pasted blocks.
type fiveNodeCollector struct {
	name string
	dir  string
	port int
	ip   string
}

func TestDistributedNCS_FiveNode(t *testing.T) {
	bin := buildArxsentinelBinary(t)

	detectorDir := t.TempDir()
	executorDir := t.TempDir()
	detectorPort := freeUDPPort(t)
	executorPort := freeUDPPort(t)
	blocklistPath := filepath.Join(executorDir, "blocklist.conf")
	idleLogPath := filepath.Join(executorDir, "idle.log")
	if err := os.WriteFile(idleLogPath, nil, 0o644); err != nil {
		t.Fatalf("create idle.log: %v", err)
	}

	collectors := []*fiveNodeCollector{
		{name: "nginx-edge", ip: "203.0.113.11"},
		{name: "api-gateway", ip: "203.0.113.12"},
		{name: "auth-service", ip: "203.0.113.13"},
	}
	for _, c := range collectors {
		c.dir = t.TempDir()
		c.port = freeUDPPort(t)
	}

	// ── Executor node — pure receiver, no outbound dial (no peers needed: TOFU
	// pinning happens on any accepted connection regardless of the peers list,
	// see transport.Transport.crossCheckPinned). Consumes scored ThreatEvents
	// from the detector under "scored-events" via a REAL executor (nginx
	// blocklist), the correct consumer for a sentinel-threat sink's opaque
	// ThreatEvent JSON — a stream `sentinel` input feeding an ordinary pipeline
	// would panic on UnwrapLogEntry, since that path always expects
	// *parser.LogEntry, not a ThreatEvent (see mode: raw's doc comment in
	// pkg/source/sentinel for why the two payload shapes are not interchangeable).
	// reload_cmd is deliberately empty — passive mode, no nginx binary needed.
	// A minimal idle stream is required only because LoadConfig always wants at
	// least one stream/pipeline; it never receives anything.
	executorConfig := fmt.Sprintf(`
general:
  pid_file: %[1]s/pid
output:
  operational_log: ""
transport:
  enabled: true
  identity: %[1]s/node.key
  known_nodes: %[1]s/known-nodes
  listen: 127.0.0.1:%[2]d
  pairing_secret: "test-mesh-pairing-secret"
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
  - name: block-scored
    type: nginx
    sources:
      - name: scored-events
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
`, executorDir, executorPort, blocklistPath, idleLogPath)

	// ── Detector node — receives raw entries from all three collectors on
	// "edge-raw" (aggregation), runs the REAL detector chain (this pipeline is
	// NOT raw_forward), and forwards each scored verdict to the executor under a
	// DIFFERENT queue_name "scored-events" (routing). transport.peers lists only
	// the executor: the detector never needs to dial the collectors, they dial it.
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
  pairing_secret: "test-mesh-pairing-secret"
streams:
  - name: detector
    pipelines:
      - name: main
        inputs:
          - type: sentinel
            addr: ncs://edge-raw
            mode: raw
            queue:
              type: transport
              mode: recv
        outputs:
          - type: sentinel-threat
            name: scored-events
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
`, detectorDir, detectorPort, executorPort)

	detectorConfigPath := filepath.Join(detectorDir, "config.yaml")
	executorConfigPath := filepath.Join(executorDir, "config.yaml")
	if err := os.WriteFile(detectorConfigPath, []byte(detectorConfig), 0o644); err != nil {
		t.Fatalf("write detector config: %v", err)
	}
	if err := os.WriteFile(executorConfigPath, []byte(executorConfig), 0o644); err != nil {
		t.Fatalf("write executor config: %v", err)
	}

	// ── Collector nodes — one per simulated source, each raw_forward-only
	// (never scores locally), each forwarding onto the SAME "edge-raw" queue_name
	// on the detector. Different transport identity per collector (separate
	// dirs → separate node.key), same destination queue_name — the aggregation
	// this test exists to prove.
	collectorLogPaths := make(map[string]string, len(collectors))
	for _, c := range collectors {
		logPath := filepath.Join(c.dir, "access.log")
		collectorLogPaths[c.name] = logPath
		if err := os.WriteFile(logPath, nil, 0o644); err != nil {
			t.Fatalf("create %s access.log: %v", c.name, err)
		}
		cfg := fmt.Sprintf(`
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
  pairing_secret: "test-mesh-pairing-secret"
streams:
  - name: %[4]s
    pipelines:
      - name: raw
        raw_forward: true
        inputs:
          - type: file
            path: %[5]s
        outputs:
          - type: sentinel-threat
            name: edge-raw
            format: raw-line
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
`, c.dir, c.port, detectorPort, c.name, logPath)
		p := filepath.Join(c.dir, "config.yaml")
		if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
			t.Fatalf("write %s config: %v", c.name, err)
		}
	}

	// ── Start order: pure receivers before dialers, so each node's listener is
	// up before whoever needs to reach it dials — not required for correctness
	// (redial handles any order), just avoids burning the 1s initial backoff on
	// a guaranteed-fail first attempt for every hop.
	cmdExecutor, outExecutor := startNode(t, bin, executorConfigPath)
	t.Cleanup(func() { stopNodeAndAssertClean(t, "executor", cmdExecutor, outExecutor) })
	time.Sleep(300 * time.Millisecond)

	cmdDetector, outDetector := startNode(t, bin, detectorConfigPath)
	t.Cleanup(func() { stopNodeAndAssertClean(t, "detector", cmdDetector, outDetector) })
	time.Sleep(300 * time.Millisecond)

	collectorOutputs := make(map[string]func() string, len(collectors))
	for _, c := range collectors {
		cmd, out := startNode(t, bin, filepath.Join(c.dir, "config.yaml"))
		name := c.name // capture for the closure
		t.Cleanup(func() { stopNodeAndAssertClean(t, name, cmd, out) })
		collectorOutputs[c.name] = out
	}

	// ── Drive traffic through each collector independently and assert its
	// distinct IP eventually reaches the executor's threats.log — proving the
	// full chain (collector → detector aggregation+scoring → executor routing)
	// for EACH of the three sources, not just "a" threat appeared somewhere.
	for _, c := range collectors {
		probeLine := accessLogLine(c.ip, "GET", "/wp-login.php", "curl/7.88")
		var found bool
		for i := 0; i < 20 && !found; i++ {
			appendLine(t, collectorLogPaths[c.name], probeLine)
			_, found = waitForFileContains(t, blocklistPath, c.ip, 1*time.Second)
		}
		if !found {
			content, _ := os.ReadFile(blocklistPath)
			t.Fatalf(
				"blocklist.conf never contained %s's forwarded IP %q after 20 attempts.\n"+
					"blocklist.conf content: %q\n\n--- %s output ---\n%s\n--- detector output ---\n%s\n--- executor output ---\n%s",
				c.name, c.ip, string(content), c.name, collectorOutputs[c.name](), outDetector(), outExecutor(),
			)
		}
	}

	// ── Final aggregation check: all three IPs must be present TOGETHER in the
	// one executor blocklist.conf — proof the fan-in from three independent
	// senders onto one queue_name landed in one place, not three separate files
	// or a last-writer-wins overwrite.
	content, err := os.ReadFile(blocklistPath)
	if err != nil {
		t.Fatalf("read blocklist.conf: %v", err)
	}
	for _, c := range collectors {
		if !strings.Contains(string(content), c.ip) {
			t.Errorf("blocklist.conf missing %s's IP %q after all three collectors sent traffic:\n%s", c.name, c.ip, content)
		}
	}
}
