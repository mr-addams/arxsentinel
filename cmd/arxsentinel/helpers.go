// ========================== Helpers =====================================================
//   Вспомогательные функции, не содержащие основной логики pipeline.
//
//   ЧТО ЗДЕСЬ:
//     - resolveTrackerGroup()           — определяет группу трекера для pipeline
//     - pipelineLogTag()                — форматирует лог-префикс stream/pipeline
//     - findPipelineCfg()               — находит конфиг pipeline по имени или индексу
//     - sinkTypeFromName()              — извлекает тип синка из Name()
//     - streamSourceLabel()             — краткое описание источника для startup-лога
//     - parseFlagInputs() / parseFlagOutputs() — разбор --input/--output CLI-флагов
//     - writePID() / removePID()        — управление PID-файлом
//     - sdNotify()                      — systemd readiness-нотификация
//     - metricsHandler()                — Prometheus metrics-endpoint с bcrypt-авторизацией
//     - activeEnvOverrides()            — диагностика ARXSENTIL_* переменных

package main

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ── TrackerGroup helpers ───────────────────────────────────────────────────────────────

// resolveTrackerGroup returns the effective tracker group key for a pipeline.
// Called from: securityFactory.Build, securityFactory.Reload (production),
// runtime_adapter.adaptConfigToStreams.
// Non-blocking.
//
// An empty TrackerGroup means isolated: use the pipeline name as the implicit group.
// Auto-wrapped pipelines (Name="", TrackerGroup="") all resolve to "" and share one tracker,
// which is the pre-Task-3 behavior for single-pipeline streams.
func resolveTrackerGroup(pipeCfg config.PipelineConfig) string {
	if pipeCfg.TrackerGroup != "" {
		return pipeCfg.TrackerGroup
	}
	return pipeCfg.Name // "" for auto-wrapped pipelines → shared tracker per stream
}

// pipelineLogTag returns a human-readable log prefix that includes stream and pipeline names.
// Called from: main, securityFactory.Reload.
// Non-blocking.
//
// Examples: "stream \"nginx\" pipeline \"api\"", "stream \"nginx\"" (unnamed pipeline).
func pipelineLogTag(streamName, pipelineName string) string {
	if streamName == "" && pipelineName == "" {
		return "(default)"
	}
	if pipelineName == "" {
		return fmt.Sprintf("stream %q", streamName)
	}
	return fmt.Sprintf("stream %q pipeline %q", streamName, pipelineName)
}

// findPipelineCfg locates the pipeline config in a (possibly updated) stream config.
// Called from: securityFactory.Build, securityFactory.Reload.
// Non-blocking.
//
// Named pipelines are matched by name; unnamed (auto-wrapped) by index.
// Returns fallback when the pipeline is not found (e.g. removed from config on SIGHUP).
func findPipelineCfg(streamCfg config.StreamConfig, name string, idx int, fallback config.PipelineConfig) config.PipelineConfig {
	if name != "" {
		for _, p := range streamCfg.Pipelines {
			if p.Name == name {
				return p
			}
		}
		return fallback // named pipeline removed from config — keep old
	}
	if idx < len(streamCfg.Pipelines) {
		return streamCfg.Pipelines[idx]
	}
	return fallback
}

// ── Source/Sink metadata ──────────────────────────────────────────────────────────────

// sinkTypeFromName extracts the sink type string from a sink Name() value.
// Called from: main.go (MetricsCallbacks.RecordOutputEvent adapter).
// Non-blocking.
//
// "file:/path/…" → "file", "stdout" → "stdout".
func sinkTypeFromName(name string) string {
	if strings.HasPrefix(name, "file:") {
		return "file"
	}
	return name
}

// streamSourceLabel returns a short human-readable source description for startup logging.
// Called from: main.
// Non-blocking.
//
// Checks pipelines when top-level inputs are absent (post-migration configs).
func streamSourceLabel(streamCfg config.StreamConfig, cfg config.Config) string {
	inputs := streamCfg.Inputs
	if len(inputs) == 0 && len(streamCfg.Pipelines) > 0 {
		// After Migrate(), inputs live in Pipelines[0].Inputs.
		inputs = streamCfg.Pipelines[0].Inputs
	}
	if len(inputs) == 0 {
		inputs = cfg.Inputs
	}
	if len(inputs) == 0 {
		return "(none)"
	}
	if inputs[0].Type == "stdin" {
		return "stdin"
	}
	return inputs[0].Path
}

// ── CLI flag helpers ──────────────────────────────────────────────────────────────────

// parseFlagInputs converts the --input flag value into an InputConfig slice.
// Called from: main.
// Non-blocking.
func parseFlagInputs(flagVal string, cfg config.Config) []config.InputConfig {
	switch flagVal {
	case "stdin":
		return []config.InputConfig{{Type: "stdin", Parser: cfg.Parser.LogFormat}}
	default:
		return []config.InputConfig{{Type: "file", Path: flagVal, Parser: cfg.Parser.LogFormat}}
	}
}

// parseFlagOutputs converts the --output flag value into a SinkConfig slice.
// Called from: main.
// Non-blocking.
//
// Accepted forms: "stdout", "stdout,json", "stdout,fail2ban".
func parseFlagOutputs(flagVal string) ([]config.SinkConfig, error) {
	parts := strings.SplitN(flagVal, ",", 2)
	sinkType := parts[0]
	format := "fail2ban"
	if len(parts) == 2 {
		format = parts[1]
	}
	switch sinkType {
	case "stdout":
		return []config.SinkConfig{{Type: "stdout", Format: format}}, nil
	default:
		return nil, fmt.Errorf("unknown output type %q; supported: stdout", sinkType)
	}
}

// ── PID file ──────────────────────────────────────────────────────────────────────────

// writePID writes the current process PID to a file.
// Called from: main.
// Non-blocking.
//
// Used for: kill -HUP $(cat pid) and logrotate postrotate.
// On error — the caller logs a warn and continues: PID is not critical.
func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removePID removes the PID file when the daemon exits.
// Called from: main via defer.
// Non-blocking.
//
// Called via defer — fires on any return from main, including SIGTERM.
// Error on removal is intentionally ignored: the file may have been deleted manually by an operator.
func removePID(path string) {
	_ = os.Remove(path)
}

// ── systemd notify ────────────────────────────────────────────────────────────────────

// sdNotify sends a state notification to systemd via NOTIFY_SOCKET.
// Called from: main.
// Non-blocking.
//
// Called once after all streams start: READY=1 marks the service active,
// STATUS= appears in `systemctl status` output.
// No-op when NOTIFY_SOCKET is absent (non-systemd environments, tests).
func sdNotify(state string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	addr := socket
	// Abstract namespace socket: "@" prefix → replace with null byte per sd_notify spec.
	if len(addr) > 0 && addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(state))
}

// ── Metrics auth ───────────────────────────────────────────────────────────────────────

// metricsHandler wraps promhttp.Handler with optional bcrypt basic auth.
// Called from: main.
// Non-blocking.
//
// If username is empty, auth is disabled and the handler is returned as-is.
// Both username and password are always compared to prevent timing side-channels.
func metricsHandler(username, passwordHash string) http.Handler {
	inner := promhttp.Handler()
	if username == "" {
		return inner
	}
	usernameBytes := []byte(username)
	hashBytes := []byte(passwordHash)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Both checks run unconditionally to avoid timing side-channels.
		userOK := subtle.ConstantTimeCompare([]byte(u), usernameBytes) == 1
		passOK := bcrypt.CompareHashAndPassword(hashBytes, []byte(p)) == nil
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="arxsentinel metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// ── Env var diagnostics ────────────────────────────────────────────────────────────────

// activeEnvOverrides returns sorted ARXSENTINEL_* keys found in the environment.
// Called from: main.
// Non-blocking.
//
// Used at startup to log which env var overrides are active — helps users verify
// their env vars were read. Misspelled or unsupported keys produce no log but also
// no error; the user can spot them missing from the output.
func activeEnvOverrides() []string {
	prefix := "ARXSENTINEL_"
	var vars []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, prefix) {
			if idx := strings.IndexByte(e, '='); idx > 0 {
				vars = append(vars, e[:idx])
			}
		}
	}
	sort.Strings(vars)
	return vars
}
