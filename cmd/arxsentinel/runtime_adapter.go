// ========================== Runtime adapter — config → StreamSpec ========================
//
//	This file is the bridge between the Product config (config.Config) and the
//	runtime contract (StreamSpec / PipelineSpec). There is NO security logic
//	here — only the construction of runtime.Run arguments from the YAML config.
//
//	WHAT IS HERE:
//	  - adaptConfigToStreams() — build []runtime.StreamSpec (one per stream)
//	    + []chan struct{} (reload channels for SIGHUP fan-out, indices = cfg.Streams).
//
//	CONNECTION TO DECISIONS.md:
//	  - Sources/Sinks are built here via buildSources/buildSinks and placed
//	    into PipelineSpec.Sources/Sinks — the engine does not build them (DECISION Q2).
//	  - Detectors are NOT placed into PipelineSpec — they are passed via the
//	    factory.Build closure (Q1: scorer→Product).
//	  - ShutdownTimeout = 5s by default; no config field yet (Phase 4+).
package main

import (
	"context"
	"fmt"
	"time"

	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ++++++++++++++++++++++++++ adaptConfigToStreams ++++++++++++++++++++++++++++++++++++++++++

// adaptConfigToStreams builds one runtime.StreamSpec for each cfg.Streams[i].
// Returns:
//
//	streams    — slice of specs ready for runtime.Run;
//	reloadChs  — slice of SIGHUP channels, indices match cfg.Streams (main.go
//	             replaces existing reloadChs with the returned ones — SIGHUP
//	             fan-out is forwarded into the engine via factory.Reload).
//
// On sources/sinks build error — partial result + error is returned;
// the engine has not started yet, the error is fatal in main.go.
//
// ctx — app context for buildSinks (sink.Reload opens files).
func adaptConfigToStreams(ctx context.Context, cfg config.Config) ([]coreruntime.StreamSpec, []chan struct{}, error) {
	streams := make([]coreruntime.StreamSpec, 0, len(cfg.Streams))
	reloadChs := make([]chan struct{}, 0, len(cfg.Streams))

	for _, streamCfg := range cfg.Streams {
		// PipelineSpecs for a single stream.
		pipelines := make([]coreruntime.PipelineSpec, 0, len(streamCfg.Pipelines))
		for j, pipeCfg := range streamCfg.Pipelines {
			// Sources/Sinks are built here (not in factory) — the engine is
			// unaware of the Product's config domain.
			sources, err := buildSources(cfg, pipeCfg.Inputs)
			if err != nil {
				return nil, nil, fmt.Errorf("stream %q pipeline %d sources: %w", streamCfg.Name, j, err)
			}
			sinks, err := buildSinks(ctx, streamCfg.Name, pipeCfg.Outputs)
			if err != nil {
				return nil, nil, fmt.Errorf("stream %q pipeline %d sinks: %w", streamCfg.Name, j, err)
			}

			pipelines = append(pipelines, coreruntime.PipelineSpec{
				Name:    pipeCfg.Name,
				Idx:     j,
				Sources: sources,
				Sinks:   sinks,
			})
		}

		// BufferSize: per-pipeline override → stream default → engine fallback (1000).
		// The adapter takes the first pipeline override; if 0 — engine applies defaultBufferSize.
		bufSize := int(cfg.Pipeline.BufferSize)
		if len(streamCfg.Pipelines) > 0 && streamCfg.Pipelines[0].Pipeline.BufferSize > 0 {
			bufSize = int(streamCfg.Pipelines[0].Pipeline.BufferSize)
		}

		// TrackerGroup: take the resolver from the first pipeline (for engine logs).
		// The runtime itself does not use this field — kept for compatibility with
		// the original pool config; the engine ignores it (DECISIONS.md).
		tg := ""
		if len(streamCfg.Pipelines) > 0 {
			tg = resolveTrackerGroup(streamCfg.Pipelines[0])
		}

		streams = append(streams, coreruntime.StreamSpec{
			Name:            streamCfg.Name,
			TrackerGroup:    tg,
			BufferSize:      bufSize,
			ShutdownTimeout: 5 * time.Second, // no cfg field yet; engine honors non-zero
			StatsInterval:   time.Duration(cfg.General.StatsInterval),
			Pipelines:       pipelines,
		})

		reloadChs = append(reloadChs, make(chan struct{}, 1))
	}

	return streams, reloadChs, nil
}
