//go:build container

// ========================== Container integration tests ==================================
//
//   Tests that verify the published Docker image behaves correctly end-to-end.
//   Requires a running Docker daemon and the arxsentinel image built locally:
//
//     docker build --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .
//     go test -v -tags container ./tests/container/ -timeout 120s
//
//   NOT included in regular go test ./...: requires Docker daemon and a pre-built image.
//   Run in CI only after the docker build step.
//
//   Test matrix:
//     1. TestContainerStartsAndExposesMetrics — image boots, /metrics returns 200
//     2. TestContainerDetectsThreat           — synthetic log → threat log written correctly
//     3. TestContainerRunsAsNonRoot           — uid must not be 0
//     4. TestContainerSurvivesSIGHUP          — SIGHUP does not crash the process
//
// =========================================================================================

package container_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	moby "github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testImage is the locally-built image used across all container tests.
const testImage = "arxsentinel:local"

// metricsPort is the default Prometheus metrics port defined in config defaults.
const metricsPort = "9117/tcp"

// minimalMetricsConfig is a minimal ArxSentinel config that enables metrics and
// points at an empty log file — sentinel starts without data and exposes /metrics.
// Logs go to /tmp which is writable by the nonroot container uid (65532).
const minimalMetricsConfig = `
general:
  log_file: /input/access.log
  pid_file: /tmp/arxsentinel.pid
logging:
  debug: false
  console_color: false
metrics:
  enabled: true
  listen_addr: ":9117"
  username: ""
  password_hash: ""
output:
  threat_log: /tmp/threats.log
  operational_log: /tmp/sentinel.log
`

// threatTestConfig is a config that tails a log file we mount into the container.
// operational_log goes to /tmp (always writable by nonroot uid 65532).
// threat_log goes to /output which is a writable bind-mount supplied by the test.
// debug: true enables the TAIL tag — required for wait.ForLog("watching started").
const threatTestConfig = `
general:
  log_file: /input/access.log
  pid_file: /tmp/arxsentinel.pid
  tail_retry_interval: "1s"
logging:
  debug: true
  console_color: false
metrics:
  enabled: false
  listen_addr: ":9117"
  username: ""
  password_hash: ""
output:
  threat_log: /output/threats.log
  operational_log: /tmp/sentinel.log
`

// ── Test 1: metrics endpoint ──────────────────────────────────────────────────────────────

func TestContainerStartsAndExposesMetrics(t *testing.T) {
	ctx := context.Background()

	cfgFile := writeTempConfig(t, minimalMetricsConfig)
	// Empty log file — sentinel opens it at EOF (pos 0) and waits for writes.
	// Allows startup to succeed without needing real log data for this test.
	emptyLog := writeEmptyInputLog(t)

	req := testcontainers.ContainerRequest{
		Image:        testImage,
		ExposedPorts: []string{metricsPort},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(cfgFile, "/etc/arxsentinel/config.yaml"),
			testcontainers.BindMount(emptyLog, "/input/access.log"),
		),
		WaitingFor: wait.ForHTTP("/metrics").
			WithPort("9117/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "9117")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}

	url := fmt.Sprintf("http://%s:%s/metrics", host, port.Port())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "go_goroutines") {
		t.Errorf("/metrics body missing go_goroutines — Prometheus registry not working\nbody:\n%s", body)
	}
}

// ── Test 2: threat detection via mounted log ──────────────────────────────────────────────

func TestContainerDetectsThreat(t *testing.T) {
	ctx := context.Background()

	// Attacker 10.0.0.1: sqlmap UA + probe paths → THREAT.
	// Legitimate 10.0.0.2: normal browser UA + 200 responses → no threat.
	syntheticLog := filepath.Join(findProjectRoot(t), "testdata", "synthetic.access.log")
	syntheticContent, err := os.ReadFile(syntheticLog)
	if err != nil {
		t.Fatalf("testdata/synthetic.access.log not found: %v", err)
	}

	// Start with an empty file so TailReader seeks to pos 0 (EOF of empty file).
	// After the container starts, we append the synthetic content — inotify fires
	// WRITE events and sentinel processes the lines from pos 0.
	inputLog := writeEmptyInputLog(t)

	outputDir := t.TempDir()
	// World-writable so the nonroot container user (uid 65532) can create threats.log.
	if err := os.Chmod(outputDir, 0o777); err != nil {
		t.Fatalf("chmod output dir: %v", err)
	}

	cfgFile := writeTempConfig(t, threatTestConfig)

	req := testcontainers.ContainerRequest{
		Image: testImage,
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(cfgFile, "/etc/arxsentinel/config.yaml"),
			testcontainers.BindMount(inputLog, "/input/access.log"),
			testcontainers.BindMount(outputDir, "/output"),
		),
		// Wait until TailReader has opened the file and is watching for writes.
		// "watching started" is logged by TailReader.Run immediately after seek(EOF).
		// Without this synchronization, the host may write log content before the
		// container's sentinel has opened the fd — the WRITE inotify event would fire
		// but sentinel would seek past the content to the new EOF and miss all lines.
		WaitingFor: wait.ForLog("watching started").
			WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	// Append synthetic log content — TailReader sees WRITE event and reads from pos 0.
	f, err := os.OpenFile(inputLog, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open input log for append: %v", err)
	}
	if _, err := f.Write(syntheticContent); err != nil {
		f.Close()
		t.Fatalf("write synthetic log content: %v", err)
	}
	_ = f.Close()

	threatLog := filepath.Join(outputDir, "threats.log")

	// Poll until threat log is non-empty or timeout.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(threatLog); err == nil && len(content) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	content, err := os.ReadFile(threatLog)
	if err != nil {
		// Print container logs to aid debugging.
		if logs, lerr := c.Logs(ctx); lerr == nil {
			buf, _ := io.ReadAll(logs)
			t.Logf("container logs:\n%s", buf)
		}
		t.Fatalf("threat log not written within 20s: %v", err)
	}

	lines := string(content)
	t.Logf("threat log content:\n%s", lines)

	// Assertion 1: attacker must be caught.
	const attackerIP = "10.0.0.1"
	if !strings.Contains(lines, " THREAT ") || !strings.Contains(lines, " "+attackerIP+" ") {
		t.Errorf("expected THREAT for attacker %s in threat log, not found", attackerIP)
	}

	// Assertion 2: legitimate IP must be absent.
	const legitimateIP = "10.0.0.2"
	for _, line := range strings.Split(lines, "\n") {
		if strings.Contains(line, " "+legitimateIP+" ") {
			t.Errorf("false positive: legitimate IP %s appeared in threat log: %s", legitimateIP, line)
		}
	}

	// Assertion 3: all non-empty threat lines match the Fail2Ban regex structure.
	scanner := bufio.NewScanner(strings.NewReader(lines))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if !strings.Contains(line, "score=") || !strings.Contains(line, "reason=") {
			t.Errorf("threat line does not match expected format: %s", line)
		}
	}
}

// ── Test 3: non-root uid ─────────────────────────────────────────────────────────────────

func TestContainerRunsAsNonRoot(t *testing.T) {
	ctx := context.Background()

	cfgFile := writeTempConfig(t, minimalMetricsConfig)
	emptyLog := writeEmptyInputLog(t)

	req := testcontainers.ContainerRequest{
		Image:        testImage,
		ExposedPorts: []string{metricsPort},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(cfgFile, "/etc/arxsentinel/config.yaml"),
			testcontainers.BindMount(emptyLog, "/input/access.log"),
		),
		WaitingFor: wait.ForHTTP("/metrics").
			WithPort("9117/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	// Inspect via the Container.Inspect() method — distroless has no shell for exec.
	// Config.User is set at image build time by the USER instruction in the Dockerfile.
	dc, ok := c.(*testcontainers.DockerContainer)
	if !ok {
		t.Skip("container is not a DockerContainer, skipping uid check")
	}

	info, err := dc.Inspect(ctx)
	if err != nil {
		t.Fatalf("container inspect: %v", err)
	}

	user := info.Config.User
	t.Logf("container Config.User: %q", user)

	if user == "0" || user == "root" || user == "" {
		t.Errorf("container runs as root (User=%q), expected nonroot uid 65532", user)
	}
}

// ── Test 4: SIGHUP survives ───────────────────────────────────────────────────────────────

func TestContainerSurvivesSIGHUP(t *testing.T) {
	ctx := context.Background()

	cfgFile := writeTempConfig(t, minimalMetricsConfig)
	emptyLog := writeEmptyInputLog(t)

	req := testcontainers.ContainerRequest{
		Image:        testImage,
		ExposedPorts: []string{metricsPort},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(cfgFile, "/etc/arxsentinel/config.yaml"),
			testcontainers.BindMount(emptyLog, "/input/access.log"),
		),
		WaitingFor: wait.ForHTTP("/metrics").
			WithPort("9117/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	// Send SIGHUP via Docker API — no shell needed (distroless).
	// testcontainers.NewDockerClientWithOpts returns a raw Docker SDK client.
	dockerClient, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Skipf("docker client not available, skipping SIGHUP test: %v", err)
	}
	defer dockerClient.Close()

	if _, err := dockerClient.ContainerKill(ctx, c.GetContainerID(), moby.ContainerKillOptions{Signal: "SIGHUP"}); err != nil {
		t.Fatalf("ContainerKill SIGHUP: %v", err)
	}

	// Wait for config reload to complete.
	time.Sleep(2 * time.Second)

	// Container must still be running after SIGHUP.
	state, err := c.State(ctx)
	if err != nil {
		t.Fatalf("container state: %v", err)
	}
	if !state.Running {
		// Dump logs to help diagnose a crash.
		if logs, lerr := c.Logs(ctx); lerr == nil {
			buf, _ := io.ReadAll(logs)
			t.Logf("container logs:\n%s", buf)
		}
		t.Errorf("container exited after SIGHUP (status=%s)", state.Status)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────────

// writeTempConfig writes config content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "arxsentinel-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := io.WriteString(f, content); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	_ = f.Close()
	// Container runs as nonroot (uid 65532) — make config world-readable.
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		t.Fatalf("chmod temp config: %v", err)
	}
	return f.Name()
}

// writeEmptyInputLog creates an empty, world-readable file to act as the sentinel's
// log_file. TailReader seeks to EOF on open (pos 0 for empty file), so content written
// after container start will be read from the beginning.
func writeEmptyInputLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("create empty input log: %v", err)
	}
	return path
}

// findProjectRoot walks up from the working directory to find the go.mod root.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from %s", dir)
		}
		dir = parent
	}
}
