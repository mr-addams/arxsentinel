// ========================== Module input/sentinel =======================================
//   SentinelThreatSource — reads JSON threat lines from a file and delivers
//   *plugin.LogEntry values with ThreatData populated to the pipeline.
//
//   This source type is used in forwarder mode: a sidecar sentinel writes threat
//   events as JSON lines, and this source reads them for re-ban on a central node.
//
//   WHAT IS HERE:
//     - SentinelThreatSource — implements plugin.Source for sentinel-threat JSON lines
//
//   WHAT IS NOT HERE:
//     - FileSource (file.go) — for raw access log parsing
//     - JSON line format (internal/core/output/format.go — sentinelThreatLine)
//
//   DEPENDENCY NOTE:
//     SentinelThreatSource reuses utils.TailReader for file watching and logrotate
//     support, same as FileSource. But it does NOT use a parser.Parser — it parses
//     JSON directly into a sentinelThreatLine struct.

package input

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// sentinelThreatLine mirrors the JSON structure from format.go for parsing.
// Each field corresponds to a field in the sentinel-threat JSON transport format.
type sentinelThreatSourceLine struct {
	TS      string   `json:"ts"`
	IP      string   `json:"ip"`
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Modules []string `json:"modules"`
	Reason  string   `json:"reason"`
	Source  string   `json:"source"`
}

// SentinelThreatSource reads JSON lines from a file and parses each into
// a *plugin.LogEntry with ThreatData populated.
//
// Unlike FileSource, it does not use a parser.Parser — it reads the JSON
// transport format produced by FormatSentinelThreat (output/format.go).
type SentinelThreatSource struct {
	name          string // "sentinel-threat:/path/to/threats.json"
	path          string
	retryInterval time.Duration
	logFn         func(tag, msg, level string)

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// NewSentinelThreatSource creates a SentinelThreatSource for the given path.
func NewSentinelThreatSource(path string, retryInterval time.Duration, logFn func(tag, msg, level string)) (*SentinelThreatSource, error) {
	if path == "" {
		return nil, fmt.Errorf("sentinel-threat source: path must not be empty")
	}
	if retryInterval <= 0 {
		retryInterval = 5 * time.Second
	}
	lf := logFn
	if lf == nil {
		lf = utils.Log
	}
	return &SentinelThreatSource{
		name:          "sentinel-threat:" + path,
		path:          path,
		retryInterval: retryInterval,
		logFn:         lf,
	}, nil
}

func (s *SentinelThreatSource) Name() string { return s.name }

func (s *SentinelThreatSource) Close() error { return nil }

func (s *SentinelThreatSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run starts the TailReader and delivers parsed entries to out.
// Blocks until ctx is cancelled. Does not close out — Merge() owns the channel.
func (s *SentinelThreatSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	lines := make(chan string, defaultLinesBufSize)
	tail := utils.NewTailReader(s.path, lines, s.retryInterval)
	go tail.Run(ctx)

	for line := range lines {
		s.linesRead.Add(1)

		var raw sentinelThreatSourceLine
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			s.parseErrors.Add(1)
			s.logFn("PARSER", fmt.Sprintf("sentinel-threat source %s: skipping malformed JSON line: %.80s", s.path, line), "debug")
			continue
		}

		ts, err := time.Parse(time.RFC3339, raw.TS)
		if err != nil {
			ts = time.Now()
		}

		entry := &plugin.LogEntry{
			RealIP: raw.IP,
			Time:   ts,
			ThreatData: &plugin.ThreatEvent{
				Timestamp: ts,
				IP:        raw.IP,
				Score:     raw.Score,
				Level:     raw.Level,
				Modules:   raw.Modules,
				Reason:    raw.Reason,
				Stream:    raw.Source,
			},
		}

		select {
		case out <- entry:
		default:
			s.dropped.Add(1)
		}
	}
	return nil
}

func init() {
	pkgsource.Register("sentinel-threat", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return NewSentinelThreatSource(cfg.Path, opts.RetryInterval, opts.LogFn)
	})
}
