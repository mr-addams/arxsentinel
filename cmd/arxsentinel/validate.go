// ========================== validate subcommand ==========================================
//   Pipeline semantic validation: checks that adjacent plugins agree on DataType.
//   Runs in two modes:
//     - arxsentinel validate [--config=path] : static check, exit 0/1
//     - daemon startup                        : fail-fast before Hub initialisation
//   Entry point: runValidateSubcommand. Called from: main (line 163).

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	pkgdetector "github.com/mr-addams/arxsentinel/pkg/detector"
	pkgexecutor "github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/pipeline"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
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
	var hasDetectors []bool
	var sinkChannels [][]string // sentinel-threat sink names per pipeline, parallel to pipes

	for _, s := range cfg.Streams {
		for _, pl := range s.Pipelines {
			pipeCtx, hd := buildPipelineCtx(s.Name, pl)
			pipes = append(pipes, pipeCtx)
			hasDetectors = append(hasDetectors, hd)
			sinkChannels = append(sinkChannels, sentinelChannelNames(pl))
		}
	}

	// Validate each pipeline (spine + terminals). The result carries ProducedType,
	// reused below to build channel types — no second spine computation.
	results := pipeline.ValidatePipelines(pipes, hasDetectors)

	// Map each sentinel-threat sink name → the produced type of its pipeline.
	channelTypes := map[string]plugin.DataType{}
	for i, r := range results {
		for _, name := range sinkChannels[i] {
			channelTypes[name] = r.ProducedType
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
func buildPipelineCtx(streamName string, pl config.PipelineConfig) (pipeline.PipelineContext, bool) {
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
	}, hd
}

// sentinelChannelNames returns the names of all sentinel-threat sinks in a pipeline.
// Called from: validateConfig (line 59).
// Non-blocking.
//
// These are the NamedChannelSwitch channels executors wire to via sources[].name.
func sentinelChannelNames(pl config.PipelineConfig) []string {
	var names []string
	for _, out := range pl.Outputs {
		if out.Type == "sentinel-threat" && out.Name != "" {
			names = append(names, out.Name)
		}
	}
	return names
}
