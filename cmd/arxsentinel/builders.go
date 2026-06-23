// ========================== Pipeline builders =========================================
//   Функции построения компонентов pipeline: detectors, sources, sinks, parser.
//
//   ЧТО ЗДЕСЬ:
//     - buildPipelineDetectors()        — собирает список детекторов из registry (pkg/detector)
//     - globalDetectorSpecs()           — конвертирует глобальный cfg.Detectors в registry-формат
//     - bridgeShared()                  — адаптирует SharedResources → pkgdetector.SharedResources
//     - detectorShared                  — реализация pkgdetector.SharedResources
//     - buildParserForInput()           — выбор парсера по profile/input-конфигурации
//     - buildSources() / buildSinks()   — построение списка плагинов из pipeline-конфига
//     - formatterForFormat()            — мост format-string → concrete format.Formatter
//                                         (Phase 2.2, Flow 083 RESOLVED-Z12).

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	pkgdetector "github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
	sinkformat "github.com/mr-addams/arx-core/pkg/sink/format"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"

	// Blank-import built-in sink plugins so their init() registers them with
	// the global sink registry before buildSinks() looks them up by name
	// (e.g. cfg.outputs[].type == "file"). Previously these imports lived in
	// pipeline.go (Flow 081 Phase 3); pipeline.go no longer carries plugin
	// concerns post-Phase-4, so the registration stays here next to its only
	// consumer.
	_ "github.com/mr-addams/arx-core/pkg/sink/file"
)

// detectorShared адаптирует main.go's SharedResources к pkgdetector.SharedResources.
// *blocklist.Manager удовлетворяет pkgdetector.Matcher неявно (имеет Match(list, text) bool).
type detectorShared struct {
	blocklist pkgdetector.Matcher
}

// Blocklist реализует pkgdetector.SharedResources.
func (s detectorShared) Blocklist() pkgdetector.Matcher { return s.blocklist }

// bridgeShared оборачивает SharedResources в интерфейс pkgdetector.SharedResources.
// Возвращает nil когда shared.BlocklistManager равен nil — тогда фабрики детекторов (badbot)
// получают nil SharedResources и используют noopMatcher вместо non-nil интерфейса,
// оборачивающего nil *blocklist.Manager (который вызвал бы panic на MatchResult).
func bridgeShared(shared SharedResources) pkgdetector.SharedResources {
	if shared.BlocklistManager == nil {
		return nil
	}
	return detectorShared{blocklist: shared.BlocklistManager}
}

// buildPipelineDetectors constructs the detector list for a pipeline.
// Called from: securityFactory.Build, securityFactory.Reload (production),
// unit tests (TestBuildPipelineDetectors_NilFallsBackToGlobal).
// Non-blocking.
//
// If pipeCfg.Detectors is nil (auto-wrapped legacy pipeline), all registered detectors
// are built from the global cfg.Detectors section — preserving backward compat so that
// detectors.rate.threshold=50 in config.yaml continues to work unchanged.
//
// If pipeCfg.Detectors is set (new pipeline syntax), only the listed detectors are built.
// Unknown detector names are logged as warnings and skipped (forward compat).
//
// ctx is passed to detector.Build() for factories that need pipeline context
// (e.g., execplugin.NewDetector receives ctx for subprocess lifecycle).
func buildPipelineDetectors(ctx context.Context, cfg config.Config, pipeCfg config.PipelineConfig, shared SharedResources) []plugin.Detector {
	ds := bridgeShared(shared)

	var specs map[string]pkgdetector.DetectorConfig
	if pipeCfg.Detectors == nil {
		specs = globalDetectorSpecs(cfg)
	} else {
		specs = make(map[string]pkgdetector.DetectorConfig, len(pipeCfg.Detectors))
		for name, dc := range pipeCfg.Detectors {
			specs[name] = pkgdetector.DetectorConfig{
				Enabled: dc.Enabled,
				Params:  dc.Params,
				Exec:    dc.Exec,
			}
		}
	}

	// Детерминированный порядок: сортируем ключи map перед итерацией.
	// Без сортировки порядок детекторов в Scorer менялся между запусками,
	// что затрудняет отладку и нарушает детерминизм тестов.
	sortedNames := make([]string, 0, len(specs))
	for name := range specs {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	var detectors []plugin.Detector
	var active []string
	for _, name := range sortedNames {
		spec := specs[name]
		d, err := pkgdetector.Build(ctx, name, spec, ds)
		if err != nil {
			utils.Log("CONFIG", fmt.Sprintf("detector %q: build error: %v (skipped)", name, err), "warn")
			continue
		}
		if d == nil {
			continue // disabled
		}
		detectors = append(detectors, d)
		active = append(active, d.Name())
	}
	utils.Log("CONFIG", fmt.Sprintf("detectors: %d active (%s)",
		len(detectors), strings.Join(active, " ")), "info")
	return detectors
}

// globalDetectorSpecs converts the global cfg.Detectors section into the registry format.
// Called from: buildPipelineDetectors.
// Non-blocking.
//
// Used by buildPipelineDetectors for auto-wrapped legacy pipelines (Detectors == nil).
// Preserves all user-configured values so existing configs behave identically after Task 3.
func globalDetectorSpecs(cfg config.Config) map[string]pkgdetector.DetectorConfig {
	d := cfg.Detectors
	return map[string]pkgdetector.DetectorConfig{
		"probe": {Enabled: d.Probe.Enabled, Params: map[string]interface{}{
			"score": d.Probe.Score,
			"paths": d.Probe.Paths,
		}},
		"rate": {Enabled: d.Rate.Enabled, Params: map[string]interface{}{
			"threshold": d.Rate.Threshold,
			"window":    time.Duration(d.Rate.Window).String(),
			"score":     d.Rate.Score,
		}},
		"ua": {Enabled: d.UserAgent.Enabled, Params: map[string]interface{}{
			"scanner_score":             d.UserAgent.ScannerScore,
			"grabber_score":             d.UserAgent.GrabberScore,
			"automation_score":          d.UserAgent.AutomationScore,
			"empty_ua_score":            d.UserAgent.EmptyUAScore,
			"extra_scanner_patterns":    d.UserAgent.ExtraScannerPatterns,
			"extra_grabber_patterns":    d.UserAgent.ExtraGrabberPatterns,
			"extra_automation_patterns": d.UserAgent.ExtraAutomationPatterns,
		}},
		"bruteforce": {Enabled: d.Bruteforce.Enabled, Params: map[string]interface{}{
			"min_requests":    d.Bruteforce.MinRequests,
			"ratio_threshold": d.Bruteforce.RatioThreshold,
			"score":           d.Bruteforce.Score,
		}},
		"crawler": {Enabled: d.Crawler.Enabled, Params: map[string]interface{}{
			"min_sequential": d.Crawler.MinSequential,
			"score":          d.Crawler.Score,
		}},
		"noasset": {Enabled: d.NoAsset.Enabled, Params: map[string]interface{}{
			"min_page_requests":     d.NoAsset.MinPageRequests,
			"asset_ratio_threshold": d.NoAsset.AssetRatioThreshold,
			"score":                 d.NoAsset.Score,
			"asset_extensions":      d.NoAsset.AssetExtensions,
		}},
		"overflow": {Enabled: d.Overflow.Enabled, Params: map[string]interface{}{
			"max_url_length":    d.Overflow.MaxURLLength,
			"suspicious_params": d.Overflow.SuspiciousParams,
			"score":             d.Overflow.Score,
		}},
		"badbot": {Enabled: d.BadBot.Enabled, Params: map[string]interface{}{
			"check_ua":       d.BadBot.CheckUA,
			"check_referrer": d.BadBot.CheckReferrer,
			"score":          d.BadBot.Score,
		}},
	}
}

// buildParserForInput returns the parser for a specific InputConfig.
// Called from: buildSources.
// Non-blocking.
//
// Priority: global parser.profile → input.parser → global parser.log_format → combined.
func buildParserForInput(cfg config.Config, input config.InputConfig) (parser.Parser, error) {
	// Global profile overrides everything — same precedence as the old buildParser.
	if cfg.Parser.Profile != "" {
		factory, ok := parser.Profiles[cfg.Parser.Profile]
		if !ok {
			return nil, fmt.Errorf("unknown parser profile %q; available: %s",
				cfg.Parser.Profile, parser.AvailableProfiles())
		}
		return factory()
	}
	format := input.Parser
	if format == "" {
		format = cfg.Parser.LogFormat
	}
	switch format {
	case "json":
		return parser.NewJSONParser(cfg.Parser.JSONFields), nil
	case "regex":
		return parser.NewRegexParser(cfg.Parser.RegexPattern)
	default: // "combined", "" → combined
		return &parser.CombinedParser{}, nil
	}
}

// buildSources constructs the Source list from an explicit inputs slice.
// Called from: runtime_adapter.adaptConfigToStreams.
// Non-blocking.
func buildSources(cfg config.Config, inputs []config.InputConfig) ([]plugin.Source, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs configured")
	}
	sources := make([]plugin.Source, 0, len(inputs))
	for _, in := range inputs {
		p, err := buildParserForInput(cfg, in)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", in.Type, err)
		}
		src, err := pkgsource.Build(in.Type, pkgsource.InputConfig{
			Type:           in.Type,
			Path:           in.Path,
			Exec:           in.Exec,
			Addr:           in.Addr,
			Mode:           in.Mode,
			URL:            in.URL,
			HTTPPath:       in.HTTPPath,
			Token:          in.Token,
			TLSCert:        in.TLSCert,
			TLSKey:         in.TLSKey,
			Protocol:       in.Protocol,
			EnvelopeField:  in.EnvelopeField,
			PullInterval:   in.PullInterval,
			MaxBodyBytes:   in.MaxBodyBytes,
			MaxConnections: in.MaxConnections,
		}, pkgsource.BuildOptions{
			Parser:        p,
			RetryInterval: time.Duration(cfg.General.TailRetryInterval),
			LogFn:         utils.Log,
		})
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", in.Type, err)
		}
		sources = append(sources, src)
	}
	return sources, nil
}

// buildSinks constructs the Sink list from an explicit outputs slice.
// Called from: runtime_adapter.adaptConfigToStreams.
// Non-blocking.
//
// Phase 2.2 (Flow 083 / RESOLVED-Z12): sinks now consume a format.Formatter
// interface (injected at wiring time) instead of a free-form format string.
// This function is the product-side bridge: it maps the YAML's format hint
// (cfg.outputs[].format) onto a concrete Formatter instance and threads it
// into SinkConfig.Formatter. Without this bridge the registry-built sinks
// receive a nil Formatter and fail with "formatter must not be nil" at
// stream-adaptation time — the regression fixed in Task 2.2 follow-up.
//
// streamName is required only for sentinel-threat formatters (they stamp
// the source stream into the wire format); it is ignored by file/stdout
// formatters but accepted unconditionally for signature symmetry.
func buildSinks(ctx context.Context, streamName string, outputs []config.SinkConfig) ([]plugin.Sink, error) {
	if len(outputs) == 0 {
		return nil, fmt.Errorf("no outputs configured")
	}
	sinks := make([]plugin.Sink, 0, len(outputs))
	for _, out := range outputs {
		formatter, err := formatterForFormat(out.Format, streamName)
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", out.Type, err)
		}
		sink, err := pkgsink.Build(ctx, pkgsink.SinkConfig{
			Type:      out.Type,
			Name:      out.Name,
			Path:      out.Path,
			Format:    out.Format,
			Formatter: formatter,
			Exec:      out.Exec,
		})
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", out.Type, err)
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// formatterForFormat maps the YAML format hint to a concrete format.Formatter
// implementation. Returns nil (not an error) when the sink type does not
// need serialization (e.g. exec sinks that own their own Formatter) — in
// that case out.Type != "" and the caller skips the nil check. Unknown
// format strings produce an error so misconfiguration fails fast at startup
// instead of silently producing empty threat logs.
//
// streamName is required for "sentinel-threat" format (the wire format
// embeds it); it is otherwise unused.
func formatterForFormat(format, streamName string) (sinkformat.Formatter, error) {
	switch format {
	case "", "fail2ban":
		// Empty string falls back to fail2ban — matches the pre-Phase-2.2
		// default and the Migrate() default in internal/sys/config.
		return &sinkformat.FailbanFormatter{}, nil
	case "json":
		return &sinkformat.JSONFormatter{}, nil
	case "sentinel-threat":
		return &sinkformat.SentinelFormatter{StreamName: streamName}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want fail2ban, json, or sentinel-threat)", format)
	}
}
