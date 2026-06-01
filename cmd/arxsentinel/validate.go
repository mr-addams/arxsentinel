// ========================== validate subcommand ==========================================
//   Pipeline semantic validation: checks that adjacent plugins agree on DataType.
//   Runs in two modes:
//     - arxsentinel validate [--config=path] : static check, exit 0/1
//     - daemon startup                        : fail-fast before Hub initialisation

package main

import (
	"fmt"
	"os"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	pkgdetector "github.com/mr-addams/arxsentinel/pkg/detector"
	pkgexecutor "github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/pipeline"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// runValidateSubcommand handles "arxsentinel validate [--config=path]".
// Loads config, collects manifests, runs pipeline.Validate, prints errors to stderr.
// Exits with code 1 if any semantic errors are found.
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

// validateConfig collects plugin manifests from the active config and checks type
// compatibility between adjacent pipeline stages.
// Returns nil when the config has no inputs/outputs (nothing to validate).
// Plugins with an empty Role (NopManifest scaffold) are skipped — they have not yet
// received a real manifest and cannot participate in semantic validation.
func validateConfig(cfg config.Config) []pipeline.SemanticError {
	manifests := collectManifests(cfg)
	if len(manifests) < 2 {
		return nil
	}
	return pipeline.Validate(manifests)
}

// collectManifests builds an ordered []plugin.Manifest representing the active pipeline.
// Order follows data flow: Sources → Detectors → Sinks → Executors.
// Only plugins with a non-empty Role are included (skips NopManifest placeholders).
func collectManifests(cfg config.Config) []plugin.Manifest {
	var manifests []plugin.Manifest

	// Sources
	for _, inp := range cfg.Inputs {
		p, err := pkgsource.Build(inp.Type, pkgsource.InputConfig{Type: inp.Type}, pkgsource.BuildOptions{})
		if err != nil || p == nil {
			continue
		}
		if m := p.Manifest(); m.Role != "" {
			manifests = append(manifests, m)
		}
	}

	// Detectors (use registered names; Build with disabled=false to get the manifest stub)
	for _, name := range pkgdetector.Names() {
		p, err := pkgdetector.Build(name, pkgdetector.DetectorConfig{Enabled: true}, pkgdetector.SharedResources(nil))
		if err != nil || p == nil {
			continue
		}
		if m := p.Manifest(); m.Role != "" {
			manifests = append(manifests, m)
			break // one detector is enough to represent the detector stage
		}
	}

	// Sinks
	for _, out := range cfg.Outputs {
		p, err := pkgsink.Build(pkgsink.SinkConfig{Type: out.Type})
		if err != nil || p == nil {
			continue
		}
		if m := p.Manifest(); m.Role != "" {
			manifests = append(manifests, m)
		}
	}

	// Executors
	for _, ex := range cfg.Executors {
		p, err := pkgexecutor.Build(pkgexecutor.ExecutorConfig{Name: ex.Name, Type: ex.Type})
		if err != nil || p == nil {
			continue
		}
		if m := p.Manifest(); m.Role != "" {
			manifests = append(manifests, m)
		}
	}

	return manifests
}
