// ========================== Module config/migrate ======================================
//   Auto-migration of deprecated I/O config fields to the new inputs/outputs syntax.
//   Migrate() is called by LoadConfig() after YAML parsing, before validation.
//
//   MIGRATION RULES (D9 in DECISIONS.md):
//     general.log_file + output.threat_log → top-level inputs[] / outputs[]
//     streams[i].log_file                  → streams[i].inputs[]
//     streams[i].threat_log                → streams[i].outputs[]
//     No I/O sections at all               → apply defaults
//
//   PRIORITY: new syntax (inputs/outputs) wins over legacy fields.
//   If inputs: is already set in YAML, general.log_file is silently ignored.
//
//   WHAT IS NOT HERE:
//     - Pipeline assembly (cmd/arxsentinel/main.go — Task 5)
//     - Validation (config.go validateInputs / validateSinks)

package config

import (
	"fmt"
	"time"
)

// Migrate converts deprecated I/O fields to the new inputs/outputs syntax.
// Modifies cfg in-place. Returns a (possibly empty) list of deprecation warnings
// that should be logged at WARN level by the caller.
//
// Called by LoadConfig after YAML parsing and env overrides, before validateConfig.
func Migrate(cfg *Config) []string {
	var warnings []string

	// ── Top-level migration ──────────────────────────────────────────────────────────────

	// general.log_file → inputs (only when inputs not already set by new syntax)
	if len(cfg.Inputs) == 0 && cfg.General.LogFile != "" {
		cfg.Inputs = []InputConfig{{
			Type:   "file",
			Path:   cfg.General.LogFile,
			Parser: cfg.Parser.LogFormat,
		}}
		warnings = append(warnings, fmt.Sprintf(
			"general.log_file is deprecated; use inputs: [{type: file, path: %q}]",
			cfg.General.LogFile,
		))
	}

	// output.threat_log → outputs (only when outputs not already set by new syntax)
	if len(cfg.Outputs) == 0 && cfg.Output.ThreatLog != "" {
		cfg.Outputs = []SinkConfig{{
			Type:   "file",
			Path:   cfg.Output.ThreatLog,
			Format: "fail2ban",
		}}
		warnings = append(warnings, fmt.Sprintf(
			"output.threat_log is deprecated; use outputs: [{type: file, path: %q, format: fail2ban}]",
			cfg.Output.ThreatLog,
		))
	}

	// Defaults when no I/O sections at all — preserves the out-of-the-box experience.
	// These match the legacy defaults for general.log_file and output.threat_log.
	if len(cfg.Inputs) == 0 {
		cfg.Inputs = []InputConfig{{
			Type:   "file",
			Path:   "/var/log/nginx/access.log",
			Parser: "combined",
		}}
	}
	if len(cfg.Outputs) == 0 {
		cfg.Outputs = []SinkConfig{{
			Type:   "file",
			Path:   "/var/log/arxsentinel/threats.log",
			Format: "fail2ban",
		}}
	}

	// ── Per-stream migration ─────────────────────────────────────────────────────────────

	for i := range cfg.Streams {
		s := &cfg.Streams[i]
		streamID := fmt.Sprintf("streams[%d]", i)
		if s.Name != "" {
			streamID = fmt.Sprintf("stream %q", s.Name)
		}

		if len(s.Inputs) == 0 && s.LogFile != "" {
			s.Inputs = []InputConfig{{
				Type:   "file",
				Path:   s.LogFile,
				Parser: cfg.Parser.LogFormat,
			}}
			warnings = append(warnings, fmt.Sprintf(
				"%s.log_file is deprecated; use inputs: [{type: file, path: %q}]",
				streamID, s.LogFile,
			))
		}

		if len(s.Outputs) == 0 && s.ThreatLog != "" {
			s.Outputs = []SinkConfig{{
				Type:   "file",
				Path:   s.ThreatLog,
				Format: "fail2ban",
			}}
			warnings = append(warnings, fmt.Sprintf(
				"%s.threat_log is deprecated; use outputs: [{type: file, path: %q, format: fail2ban}]",
				streamID, s.ThreatLog,
			))
		}
	}

	// ── Pipeline config defaults ─────────────────────────────────────────────────────────
	// defaultConfig() sets top-level Pipeline defaults; only apply if still zero
	// (e.g. when a test constructs Config{} directly without calling defaultConfig).
	if cfg.Pipeline.BufferSize == 0 {
		cfg.Pipeline.BufferSize = 8192
	}
	if cfg.Pipeline.ShutdownTimeout == 0 {
		cfg.Pipeline.ShutdownTimeout = Duration(15 * time.Second)
	}

	// ── Auto-wrap: new syntax streams without explicit pipelines ──────────────────────────
	// Streams that use the Flow #030 inputs/outputs syntax (or legacy log_file fields)
	// are wrapped into a single unnamed pipeline so runStream() can always iterate
	// over Pipelines without branching on the legacy path.
	// Streams that already declare pipelines: are left untouched.
	for i := range cfg.Streams {
		s := &cfg.Streams[i]
		if len(s.Pipelines) > 0 {
			continue // new syntax — auto-wrap not needed
		}
		if len(s.Inputs) == 0 && len(s.Outputs) == 0 && s.Executors == nil {
			continue
		}
		runtime := s.Pipeline
		if runtime.BufferSize == 0 {
			runtime.BufferSize = cfg.Pipeline.BufferSize
		}
		if runtime.ShutdownTimeout == 0 {
			runtime.ShutdownTimeout = cfg.Pipeline.ShutdownTimeout
		}
		s.Pipelines = []PipelineConfig{{
			Name:         "",
			TrackerGroup: "",
			Inputs:       s.Inputs,
			Outputs:      s.Outputs,
			Pipeline:     runtime,
		}}
	}

	return warnings
}
