// LogAggregator example — a telemetry pipeline built purely on arx-core/pkg/*.
// The runtime drives a syslog source through a severity and substring filter
// (LineProcessor) into a JSON file sink. The example exists to prove the
// arx-core runtime is generic.
//
// Pipeline:
//
//	syslog source (pkg/source/syslog)  --*plugin.Event-->  FilterProcessor
//	                                                              |
//	                                                              v
//	                                                     JSON file sink
//
// All imports are under github.com/mr-addams/arx-core/pkg/*; blank-imports
// register "syslog" and "file" factories through their package init() hooks.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arx-core/pkg/sink"
	"github.com/mr-addams/arx-core/pkg/source"

	// Blank-imports wire plugin factories through their package init() hooks.
	// Removing either line breaks the build because source.Build("syslog", ...)
	// and sink.Build(ctx, {Type: "file", ...}) would return "unknown" errors.
	_ "github.com/mr-addams/arx-core/pkg/sink/file"
	_ "github.com/mr-addams/arx-core/pkg/source/syslog"
)

func main() {
	addr := flag.String("addr", "udp://:5514", "syslog listen address (udp://, tcp://, unix://, unixgram://)")
	out := flag.String("out", "./logaggregator-out.json", "output JSON-lines file path")
	severity := flag.String("severity", "", "minimum severity to keep: DEBUG|INFO|WARN|ERROR (empty = no gate)")
	substring := flag.String("substring", "", "only keep records whose message contains this substring (empty = no gate)")
	flag.Parse()

	logFn := func(tag, msg, level string) {
		fmt.Fprintf(os.Stderr, "[LAg] %s %s %s\n", tag, level, msg)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Source — built through the source registry so the example uses the same
	// plugin-assembly path product code uses. The parser is injected via
	// BuildOptions; the syslog source hands each incoming line to the parser
	// after stripping the RFC 3164/5424 envelope.
	src, err := source.Build("syslog", source.InputConfig{Addr: *addr}, source.BuildOptions{
		Parser: &parser.CombinedParser{},
		LogFn:  logFn,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "source build:", err)
		os.Exit(1)
	}
	defer src.Close()

	// Sink — built through the sink registry with the example's Formatter.
	// The file sink appends '\n' itself; the Formatter returns bytes only.
	fileSink, err := sink.Build(ctx, sink.SinkConfig{
		Type:      "file",
		Path:      *out,
		Formatter: &JSONFormatter{},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sink build:", err)
		os.Exit(1)
	}
	defer fileSink.Close()

	// Pipeline spec — single pipeline "main" with one source and one sink.
	// BufferSize and StatsInterval are tuning knobs on StreamSpec; defaults
	// from runtime/engine.go also work, but explicit values make the
	// example self-documenting.
	spec := runtime.StreamSpec{
		Name:          "logaggregator",
		BufferSize:    1000,
		StatsInterval: 30 * time.Second,
		Pipelines: []runtime.PipelineSpec{
			{
				Name:    "main",
				Idx:     0,
				Sources: []plugin.Source{src},
				Sinks:   []plugin.Sink{fileSink},
			},
		},
	}

	// Filter — owns both halves of the runtime contract. Engine type-asserts
	// factory.(LineProcessor) and fails fast if the same type does not
	// implement both interfaces. severity/substring are empty defaults that
	// disable each gate independently.
	filter := &FilterProcessor{
		minSeverity: *severity,
		substring:   *substring,
	}

	if err := runtime.Run(ctx, spec, filter, runtime.SharedResources{}, nil, logFn); err != nil {
		fmt.Fprintln(os.Stderr, "runtime:", err)
		os.Exit(1)
	}
}