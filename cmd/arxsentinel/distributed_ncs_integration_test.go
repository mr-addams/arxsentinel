//go:build integration

// ========================== Distributed NCS integration test (Flow 093 Group H) ==========
//   End-to-end acceptance tests for the raw-forward pipeline: a "collector" node
//   parses a raw access-log line, forwards it UNSCORED over the real QUIC
//   transport (arx-core Distributed NCS) to a "detector" node, which runs it
//   through the real bruteforce/probe detector chain and writes a scored
//   threat-log line.
//
//   This exercises the full wiring built across Flow 093 Groups E/F/G in one
//   test: two real arxsentinel subprocesses, TOFU-pinned QUIC dial, a
//   transport-backed sentinel-threat sink (mode: send) on the collector and a
//   transport-backed sentinel source (mode: raw + queue mode: recv) on the
//   detector, and the detector's ordinary (non-RawForward) pipeline scoring
//   the forwarded LogEntry as if it arrived locally.
//
//   Run: go test -tags integration -run TestDistributedNCS -v ./cmd/arxsentinel/
//
//   NOT included in `go test ./...` — spawns real subprocesses and a real
//   QUIC handshake, which is slower and less hermetic than the unit-level
//   tests covering the same wiring pieces individually (config validation,
//   preRegisterSinkQueues/preRegisterInboundTransportQueues, RawLineFormatter,
//   securityProcessor's RawForward branch). These tests' job is to prove those
//   pieces compose correctly across a process boundary — a failure here means
//   a wiring regression that no unit test can see.
//
//   TEST MATRIX:
//     TestDistributedNCS_RawForwardToDetector          — positive control:
//       malicious traffic IS scored and forwarded to threats.log.
//     TestDistributedNCS_BenignTrafficNotForwardedAsThreat — negative control,
//       WITH an embedded positive check: benign traffic must NOT appear in
//       threats.log, and a subsequent malicious burst in the SAME run MUST
//       appear — proving the absence is real detector selectivity, not a
//       silently-broken pipeline that would also produce "no output" for any
//       input.
//     TestDistributedNCS_CleanShutdown — both nodes exit 0 on SIGTERM (no
//       panic / no goroutine deadlock during transport + stream teardown).

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// freeUDPPort returns an available UDP port on 127.0.0.1 by binding to
// port 0 and releasing it immediately. There is an inherent TOCTOU race
// (nothing prevents another process from grabbing the port before the
// transport binds it), but it is the same trick arx-core's own transport
// tests use and is good enough for a local, single-machine test run.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("freeUDPPort: close: %v", err)
	}
	return port
}

// buildArxsentinelBinary compiles the current package (cmd/arxsentinel) into
// a temp binary once per test process (memoized via sync.OnceValues) —
// building it fresh for every test function in this file would triple the
// compile cost for no benefit, since all tests exercise the same binary.
//
// Building a real binary (rather than reusing this test's own process) is
// required here: two independent nodes each need their own process-level
// transportbridge singleton, main()'s signal handling, and a clean os.Exit
// on fatal config errors — none of which can be exercised by calling main()'s
// helper functions in-process for two "nodes" at once.
var buildArxsentinelBinaryOnce = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "arxsentinel-integration-bin")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "arxsentinel-integration-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build arxsentinel: %w\n%s", err, out)
	}
	return bin, nil
})

func buildArxsentinelBinary(t *testing.T) string {
	t.Helper()
	bin, err := buildArxsentinelBinaryOnce()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return bin
}

// startNode launches the built binary with --config, capturing combined
// output into a buffer the caller can dump on failure. Returns the *exec.Cmd
// (already started) and a function that returns the captured output so far.
func startNode(t *testing.T, bin, configPath string) (*exec.Cmd, func() string) {
	t.Helper()
	cmd := exec.Command(bin, "--config", configPath)
	var mu sync.Mutex
	var out strings.Builder
	cmd.Stdout = lockedWriter{&mu, &out}
	cmd.Stderr = lockedWriter{&mu, &out}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node (config=%s): %v", configPath, err)
	}
	return cmd, func() string {
		mu.Lock()
		defer mu.Unlock()
		return out.String()
	}
}

// lockedWriter serializes concurrent writes from a subprocess's stdout and
// stderr pipes (exec.Cmd reads them on separate goroutines) into the same
// strings.Builder — an unsynchronized shared Builder would race under `go
// test -race` (which Flow 093's CI gate always runs for the non-integration
// suite; this file stays -race-clean too even though it is not part of that
// gate, so a developer running `-tags integration -race` locally does not
// hit a false alarm).
type lockedWriter struct {
	mu  *sync.Mutex
	buf *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// stopNodeAndAssertClean sends SIGTERM (matching main.go's
// signal.NotifyContext(SIGTERM) shutdown path), waits for exit, and asserts
// the process exited with code 0. A daemon that catches SIGTERM and shuts
// down through its normal goroutine-drain path always returns 0 from main();
// a non-zero code (or a Kill fallback firing) means shutdown panicked, hung,
// or otherwise did not complete cleanly — worth failing the test over, not
// just cleaning up silently.
func stopNodeAndAssertClean(t *testing.T, name string, cmd *exec.Cmd, out func() string) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	killed := false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		killed = true
		_ = cmd.Process.Kill()
		<-done
	}
	if killed {
		t.Errorf("%s: did not exit within 5s of SIGTERM — had to Kill()\n--- output ---\n%s", name, out())
		return
	}
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		t.Errorf("%s: exited with code %d after SIGTERM, want 0 (clean shutdown)\n--- output ---\n%s", name, code, out())
	}
}

// waitForFileContains polls path every 200ms until its content contains
// substr or timeout elapses. A missing file is treated as "not yet" rather
// than an error — the detector node creates threats.log lazily on first
// write, so its absence during the early polling window is expected.
func waitForFileContains(t *testing.T, path, substr string, timeout time.Duration) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastContent string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			lastContent = string(data)
			if strings.Contains(lastContent, substr) {
				return lastContent, true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return lastContent, false
}

// waitForOutputContains polls a captured-output accessor (as returned by
// startNode) every 50ms until it contains substr or timeout elapses. Used to
// detect "this node has reached signal.NotifyContext and is past its
// pre-signal-handling startup window" before sending SIGTERM — sending the
// signal any earlier races main()'s own startup sequence: SIGTERM delivered
// before signal.NotifyContext registers gets the OS default (immediate kill,
// no graceful shutdown), which is a real condition but not what
// TestDistributedNCS_CleanShutdown is testing (main.go's own shutdown path
// completing cleanly, not "does main() install its signal handler instantly").
func waitForOutputContains(out func() string, substr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(out(), substr) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// distributedNCSTopology holds the two-node collector→detector config and
// filesystem layout shared by every test in this file. accessLogPath is
// Node A's tailed input; threatsLogPath is Node B's scored output.
type distributedNCSTopology struct {
	dirA, dirB               string
	configAPath, configBPath string
	accessLogPath            string
	threatsLogPath           string
}

// newDistributedNCSTopology allocates temp dirs/ports and writes both nodes'
// config.yaml. Node A: raw_forward collector, transport sink mode=send named
// "edge-raw". Node B: transport source mode=raw + queue mode=recv on the same
// name, feeding an ordinary (scored) pipeline.
func newDistributedNCSTopology(t *testing.T) *distributedNCSTopology {
	t.Helper()
	dirA := t.TempDir()
	dirB := t.TempDir()
	portA := freeUDPPort(t)
	portB := freeUDPPort(t)

	accessLogPath := filepath.Join(dirA, "access.log")
	if err := os.WriteFile(accessLogPath, nil, 0o644); err != nil {
		t.Fatalf("create access.log: %v", err)
	}
	threatsLogPath := filepath.Join(dirB, "threats.log")

	configA := fmt.Sprintf(`
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
  - name: collector
    pipelines:
      - name: raw
        raw_forward: true
        inputs:
          - type: file
            path: %[4]s
        outputs:
          - type: sentinel-threat
            name: edge-raw
            format: raw-line
            queue:
              type: transport
              mode: send
              peer: 127.0.0.1:%[3]d
`, dirA, portA, portB, accessLogPath)

	configB := fmt.Sprintf(`
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
          - type: file
            path: %[4]s
            format: fail2ban
`, dirB, portB, portA, threatsLogPath)

	configAPath := filepath.Join(dirA, "config.yaml")
	configBPath := filepath.Join(dirB, "config.yaml")
	if err := os.WriteFile(configAPath, []byte(configA), 0o644); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(configBPath, []byte(configB), 0o644); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	return &distributedNCSTopology{
		dirA: dirA, dirB: dirB,
		configAPath: configAPath, configBPath: configBPath,
		accessLogPath: accessLogPath, threatsLogPath: threatsLogPath,
	}
}

// startTopology starts Node B (listener side) then Node A, registering
// t.Cleanup handlers that SIGTERM both and assert a clean exit. Node B goes
// first so Node A's first dial attempt does not burn the peer's 1s initial
// backoff on a guaranteed-fail try — not required for correctness (redial
// handles either order), just keeps every test's happy path fast.
func startTopology(t *testing.T, bin string, topo *distributedNCSTopology) (outA, outB func() string) {
	t.Helper()
	cmdB, ob := startNode(t, bin, topo.configBPath)
	t.Cleanup(func() { stopNodeAndAssertClean(t, "node B", cmdB, ob) })
	time.Sleep(300 * time.Millisecond)

	cmdA, oa := startNode(t, bin, topo.configAPath)
	t.Cleanup(func() { stopNodeAndAssertClean(t, "node A", cmdA, oa) })
	return oa, ob
}

// appendLine opens path for append, writes line, and closes — a fresh handle
// per call so the file's write position is never held open across the
// polling waits between appends (keeps each write's fsnotify event distinct).
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s for append: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}
}

// accessLogLine renders a combined-format access-log line for the given IP,
// method, and path — the exact fields the bruteforce/probe detectors and
// parser.CombinedParser key off (RemoteAddr, Path, UserAgent).
func accessLogLine(ip, method, path, userAgent string) string {
	return fmt.Sprintf(
		`%s - - [04/Jul/2026:10:00:00 +0000] "%s %s HTTP/1.1" 200 512 "-" "%s" "%s"`+"\n",
		ip, method, path, userAgent, ip,
	)
}

// ----------------------------------------------------------------------------------------
// Test 1 (positive control): malicious traffic IS forwarded and scored.
// ----------------------------------------------------------------------------------------

// threatLineRE matches a fail2ban-format threat line and captures the IP and
// score fields — used to assert the exact structure, not just substring
// presence, so a formatter regression (e.g. a swapped field) is caught.
var threatLineRE = regexp.MustCompile(`(WARN|THREAT)\s+(\S+)\s+score=(\d+)\s+modules=(\S*)\s+reason=`)

func TestDistributedNCS_RawForwardToDetector(t *testing.T) {
	bin := buildArxsentinelBinary(t)
	topo := newDistributedNCSTopology(t)
	outA, outB := startTopology(t, bin, topo)

	// Appended repeatedly — guarantees the bruteforce/probe detectors push
	// the accumulated score past AlertThreshold (50) regardless of any
	// single line's individual weight, and repeated appends double as a
	// retry against any startup-timing race between the transport handshake
	// completing and the file tail picking up the first write (same
	// principle as arx-core's queue tests: a single write succeeding does
	// not prove delivery — keep feeding until the effect is observed).
	const probeIP = "203.0.113.77"
	probeLine := accessLogLine(probeIP, "GET", "/wp-login.php", "curl/7.88")

	var (
		content string
		found   bool
	)
	for i := 0; i < 20 && !found; i++ {
		appendLine(t, topo.accessLogPath, probeLine)
		content, found = waitForFileContains(t, topo.threatsLogPath, probeIP, 1*time.Second)
	}

	if !found {
		t.Fatalf(
			"threats.log never contained forwarded IP %q after 20 attempts.\n"+
				"threats.log content: %q\n\n--- node A output ---\n%s\n--- node B output ---\n%s",
			probeIP, content, outA(), outB(),
		)
	}

	m := threatLineRE.FindStringSubmatch(content)
	if m == nil {
		t.Fatalf("threats.log line does not match the expected fail2ban format: %q", content)
	}
	if m[2] != probeIP {
		t.Errorf("threat line IP = %q, want %q (field-order regression?)", m[2], probeIP)
	}
	if m[3] == "0" {
		t.Errorf("threat line score = 0, want > 0")
	}
	if m[4] == "" {
		t.Errorf("threat line modules= is empty, want at least one detector name")
	}
}

// ----------------------------------------------------------------------------------------
// Test 2 (negative control + embedded positive check): benign traffic is
// forwarded (raw_forward has no local opinion) but must NOT be scored as a
// threat by Node B — proving Node B's detector chain runs for real rather
// than passing every forwarded entry through as a threat line. The trailing
// malicious burst in the SAME run proves the pipeline is genuinely alive:
// an absent threats.log entry for the benign IP is only meaningful evidence
// of selectivity if a different IP in the same run DOES produce one.
// ----------------------------------------------------------------------------------------
func TestDistributedNCS_BenignTrafficNotForwardedAsThreat(t *testing.T) {
	bin := buildArxsentinelBinary(t)
	topo := newDistributedNCSTopology(t)
	outA, outB := startTopology(t, bin, topo)

	const benignIP = "203.0.113.201"
	benignLine := accessLogLine(benignIP, "GET", "/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Five benign requests, each followed by a settle window — enough for
	// the round trip (tail → raw-forward → transport → Node B's detector
	// chain) to have completed if it were going to fire at all, without
	// racing an artificially short single wait.
	for i := 0; i < 5; i++ {
		appendLine(t, topo.accessLogPath, benignLine)
		time.Sleep(300 * time.Millisecond)
	}
	if content, err := os.ReadFile(topo.threatsLogPath); err == nil && strings.Contains(string(content), benignIP) {
		t.Fatalf(
			"threats.log unexpectedly contains benign IP %q — detector over-fired on non-malicious traffic:\n%s",
			benignIP, content,
		)
	}

	// Positive control: the same topology, right after, must still detect
	// real malicious traffic — otherwise the benign-absence check above
	// would be vacuous (a silently-dead pipeline "passes" it trivially).
	const probeIP = "203.0.113.202"
	probeLine := accessLogLine(probeIP, "GET", "/wp-login.php", "curl/7.88")

	var found bool
	for i := 0; i < 20 && !found; i++ {
		appendLine(t, topo.accessLogPath, probeLine)
		_, found = waitForFileContains(t, topo.threatsLogPath, probeIP, 1*time.Second)
	}
	if !found {
		content, _ := os.ReadFile(topo.threatsLogPath)
		t.Fatalf(
			"positive control failed: threats.log never contained %q after the benign-traffic check — "+
				"pipeline may be silently dead rather than selectively filtering.\n"+
				"threats.log content: %q\n\n--- node A output ---\n%s\n--- node B output ---\n%s",
			probeIP, string(content), outA(), outB(),
		)
	}

	// Final re-check: the earlier benign IP must still be absent even after
	// more traffic flowed through the same pipeline (rules out a delayed /
	// batched false-positive appearing only after additional throughput).
	if content, err := os.ReadFile(topo.threatsLogPath); err == nil && strings.Contains(string(content), benignIP) {
		t.Errorf("threats.log contains benign IP %q after additional traffic — delayed false positive:\n%s", benignIP, content)
	}
}

// ----------------------------------------------------------------------------------------
// Test 3: both nodes shut down cleanly (exit 0) on SIGTERM — proves the
// transport goroutine (startTransport), the stream goroutine, and the
// two NCS queue backends all tear down without panicking or hanging,
// independent of whether any traffic ever flowed.
// ----------------------------------------------------------------------------------------
func TestDistributedNCS_CleanShutdown(t *testing.T) {
	bin := buildArxsentinelBinary(t)
	topo := newDistributedNCSTopology(t)
	outA, outB := startTopology(t, bin, topo) // cleanup asserts clean exit; no traffic needed

	// Wait for both nodes to log past startTransport (which runs after
	// signal.NotifyContext in main.go's startup sequence) before letting
	// t.Cleanup send SIGTERM. Sending it any earlier races main()'s own
	// startup — a signal delivered before signal.NotifyContext registers
	// gets the OS default (immediate kill, no graceful path at all), which
	// is a real condition on a real system but a different one than what
	// this test checks (does main()'s OWN shutdown sequence complete
	// cleanly once it has actually started).
	if !waitForOutputContains(outA, "[TRANSPORT] listening", 5*time.Second) {
		t.Fatalf("node A did not log startup completion within 5s:\n%s", outA())
	}
	if !waitForOutputContains(outB, "[TRANSPORT] listening", 5*time.Second) {
		t.Fatalf("node B did not log startup completion within 5s:\n%s", outB())
	}
}

// ----------------------------------------------------------------------------------------
// Test 4: a SIGTERM sent as soon as the PID file appears still exits
// cleanly. This is the precise regression check for the bug
// TestDistributedNCS_CleanShutdown originally caught: writePID() runs AFTER
// flag parsing, config load, and logger init — in the pre-fix code,
// signal.NotifyContext was registered even LATER than that (see main.go's
// git history), so a SIGTERM landing at "the PID file just appeared" reliably
// hit the unprotected window and fell through to the OS default disposition
// (immediate kill, exit code -1, no graceful path). Now that
// signal.NotifyContext is main()'s first line — before flag parsing, before
// writePID — this same "PID file just appeared" instant is now WELL AFTER
// signal registration, so it must exit 0.
//
// Deliberately NOT testing a zero-delay SIGTERM sent the instant Start()
// returns: that races the OS's own process-exec-to-first-instruction latency
// (present in any Go binary, signal handling or not) and cannot be fixed by
// reordering code inside main() — asserting on it would be testing the OS
// scheduler, not this bug.
// ----------------------------------------------------------------------------------------
func TestDistributedNCS_ImmediateSIGTERMExitsCleanly(t *testing.T) {
	bin := buildArxsentinelBinary(t)
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "pid")

	accessLogPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(accessLogPath, nil, 0o644); err != nil {
		t.Fatalf("create access.log: %v", err)
	}
	cfgYAML := fmt.Sprintf(`
general:
  pid_file: %[1]s
output:
  operational_log: ""
streams:
  - name: minimal
    pipelines:
      - name: main
        inputs:
          - type: file
            path: %[2]s
        outputs:
          - type: file
            path: %[3]s/threats.log
            format: fail2ban
`, pidPath, accessLogPath, dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Repeated rather than a single attempt: process-start scheduling has
	// some inherent jitter even past the pid-file milestone — one passing
	// iteration does not prove the fix holds reliably, and one failing
	// iteration under host load could be a fluke. Every iteration must pass.
	const attempts = 10
	for i := 0; i < attempts; i++ {
		_ = os.Remove(pidPath) // previous iteration's pid file, if any
		cmd, out := startNode(t, bin, cfgPath)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(pidPath); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("attempt %d/%d: pid file never appeared:\n%s", i+1, attempts, out())
			}
			time.Sleep(2 * time.Millisecond)
		}
		stopNodeAndAssertClean(t, fmt.Sprintf("attempt %d/%d", i+1, attempts), cmd, out)
		if t.Failed() {
			return
		}
	}
}
