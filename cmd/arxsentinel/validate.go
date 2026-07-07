// ========================== validate subcommand ==========================================
//
//	Pipeline semantic validation: checks that adjacent plugins agree on DataType.
//	Runs in two modes:
//	  - arxsentinel validate [--config=path] : static check, exit 0/1
//	  - daemon startup                        : fail-fast before Hub initialisation
//	Entry point: runValidateSubcommand. Called from: main (line 163).
package main

import (
	"context"
	"fmt"
	"os"

	pkgdetector "github.com/mr-addams/arx-core/pkg/detector"
	pkgexecutor "github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/pipeline"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// runValidateSubcommand handles "arxsentinel validate [--config=path]".
// Called from: main (line 163).
// Non-blocking (exits via os.Exit on errors).
func runValidateSubcommand(configPath string) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel validate: config error: %v\n", err)
		os.Exit(1)
	}
	errs := validateConfig(cfg)
	if len(errs) == 0 {
		fmt.Println("arxsentinel validate: OK — no semantic errors")
		return
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "arxsentinel validate: %s\n", e)
	}
	os.Exit(1)
}

// validateConfig collects plugin manifests from the active config and runs
// topology-aware validation: spine (Source→Processors→Detectors→[Scorer]),
// terminals (each sink independently), and executor wiring (NCS name-matching).
// Called from: main (line 214), runValidateSubcommand (line 31).
// Non-blocking.
func validateConfig(cfg config.Config) []pipeline.SemanticError {
	// config.LoadConfig always runs Migrate(), which wraps any top-level inputs/outputs
	// (or the deprecated general.log_file/output.threat_log) into streams[].pipelines[].
	// So cfg.Streams is never empty here and every pipeline lives under a stream.
	var pipes []pipeline.PipelineContext
	var sinkChannels [][]string // sentinel-threat sink names per pipeline, parallel to pipes

	for _, s := range cfg.Streams {
		for _, pl := range s.Pipelines {
			pipes = append(pipes, buildPipelineCtx(s.Name, pl))
			sinkChannels = append(sinkChannels, sentinelChannelNames(pl))
		}
	}

	// Validate each pipeline (spine + terminals). The result carries ProducedType,
	// reused below to build channel types — no second spine computation.
	results := pipeline.ValidatePipelines(pipes)

	// Map each sentinel-threat sink name → the produced type of its pipeline.
	channelTypes := map[string]plugin.DataType{}
	for i, r := range results {
		for _, name := range sinkChannels[i] {
			channelTypes[name] = r.ProducedType
		}
	}

	// Flow 093 exemption: an executor source whose queue: is a transport
	// backend in mode=recv has its writer on a REMOTE node — a separate
	// process/config this validator cannot see — so ValidateExecutorWiring's
	// "reader without writer" check (step 2, arx-core/pkg/pipeline) would
	// otherwise reject it as "wired to unknown channel". Synthesizing a
	// plugin.TypeAny entry satisfies that check AND the type-compatibility
	// check right after it (TypeAny is the documented "always compatible"
	// escape hatch) without claiming to know what the remote node actually
	// produces. Mirrors the sentinelChannelNames exemption on the sink side
	// of the same cross-node pattern (preRegisterExecutorQueues has the
	// runtime-registration-time counterpart of this same exemption).
	for _, ex := range cfg.Executors {
		for _, src := range ex.Sources {
			if src.Queue == nil || src.Queue.Type != queue.QueueTypeTransport || src.Queue.EffectiveMode() != "recv" {
				continue
			}
			if _, exists := channelTypes[src.Name]; !exists {
				channelTypes[src.Name] = plugin.TypeAny
			}
		}
	}

	// Build executor bindings. An unknown executor type is a real misconfiguration —
	// surface it instead of skipping silently (the registry Build would also fail).
	var allErrs []pipeline.SemanticError
	var bindings []pipeline.ExecutorBinding
	for _, ex := range cfg.Executors {
		m, ok := pkgexecutor.ManifestByName(ex.Type)
		if !ok {
			allErrs = append(allErrs, pipeline.SemanticError{
				ConsumerType: "executor",
				ConsumerName: ex.Name,
				Note:         "unknown executor type '" + ex.Type + "'",
			})
			continue
		}
		srcNames := make([]string, 0, len(ex.Sources))
		for _, src := range ex.Sources {
			srcNames = append(srcNames, src.Name)
		}
		bindings = append(bindings, pipeline.ExecutorBinding{
			Name:        ex.Name,
			InputType:   m.InputType,
			SourceNames: srcNames,
		})
	}

	wiringErrs := pipeline.ValidateExecutorWiring(bindings, channelTypes)

	for _, r := range results {
		allErrs = append(allErrs, r.Errors...)
	}
	allErrs = append(allErrs, wiringErrs...)
	return allErrs
}

// buildPipelineCtx builds a PipelineContext from a single pipeline config.
// Called from: validateConfig (line 56).
// Non-blocking.
func buildPipelineCtx(streamName string, pl config.PipelineConfig) pipeline.PipelineContext {
	var spine []plugin.Manifest
	for _, inp := range pl.Inputs {
		// Read the static manifest from the registry — building a live file/exec
		// source would require a path and parser unavailable at validation time.
		if m, ok := pkgsource.ManifestByName(inp.Type); ok && m.Role != "" {
			spine = append(spine, m)
		}
	}

	// Detectors enable scoring (Structured → ScoredEvent). nil = section omitted =
	// "all registered detectors with defaults" → scoring on. An explicit empty map
	// (detectors: {}) means "no detectors" → ETL mode, no Scorer, spine stays Structured.
	hd := len(pl.Detectors) > 0 || pl.Detectors == nil
	if hd {
		for _, name := range pkgdetector.Names() {
			p, err := pkgdetector.Build(context.Background(), name, pkgdetector.DetectorConfig{Enabled: true}, pkgdetector.SharedResources(nil))
			if err != nil || p == nil {
				continue
			}
			if m := p.Manifest(); m.Role != "" {
				spine = append(spine, m)
				break
			}
		}
		// Product owns the Scorer-as-spine-stage convention — Core validator treats
		// spine as an arbitrary producer chain and never inserts stages on the
		// caller's behalf. Defensive copy + append so ctx.Spine's backing array
		// is never mutated for any subsequent reader.
		spine = append(append([]plugin.Manifest{}, spine...), scorerManifest)
	}

	var sinks []plugin.Manifest
	for _, out := range pl.Outputs {
		m, ok := pkgsink.ManifestByName(out.Type)
		if ok {
			sinks = append(sinks, m)
		}
	}

	return pipeline.PipelineContext{
		StreamName:   streamName,
		PipelineName: pl.Name,
		Spine:        spine,
		Sinks:        sinks,
	}
}

// scorerManifest is the product-owned synthetic manifest for the Scorer stage.
// It transforms detector output (Structured) into ScoredEvent and is appended
// to the spine when a pipeline has detectors (see buildPipelineCtx). It lives
// here, not in pkg/pipeline, because the Core validator treats spine as an
// arbitrary producer chain from config — adding Scorer-as-spine-stage is a
// product convention (Flow 083, Phase 4b).
var scorerManifest = plugin.Manifest{
	PluginID:   "scorer",
	Role:       plugin.RoleProcessor,
	InputType:  plugin.TypeStructured,
	OutputType: plugin.TypeScoredEvent,
}

// sentinelChannelNames returns the names of all sentinel-threat sinks in a
// pipeline that require a LOCAL reader (an executor's sources[].name, per
// ValidateExecutorWiring's "writer but no reader" check).
// Called from: validateConfig (line 59).
// Non-blocking.
//
// Flow 093 exemption: a sink whose queue: is a transport backend in
// mode=send has its reader on a REMOTE node's "sentinel" input (the
// receiving node's config, a separate process — see
// preRegisterInboundTransportQueues) — there is no local executor to find,
// and there never will be, so this channel is deliberately excluded from
// the "requires a local reader" set. This is the mode=send case ONLY:
// mode=both (or the default, empty mode) still means "a local reader is
// also expected on this node" per QueueConfig.Mode's doc comment, so it
// stays subject to the normal writer-without-reader check.
func sentinelChannelNames(pl config.PipelineConfig) []string {
	var names []string
	for _, out := range pl.Outputs {
		if out.Type != "sentinel-threat" || out.Name == "" {
			continue
		}
		if out.Queue != nil && out.Queue.Type == queue.QueueTypeTransport && out.Queue.EffectiveMode() == "send" {
			continue
		}
		names = append(names, out.Name)
	}
	return names
}
