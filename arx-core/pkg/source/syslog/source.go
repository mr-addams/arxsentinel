// ========================== pkg/source/syslog — syslog network source =====================
//   Implements a Source that listens for syslog messages over UDP, TCP, Unix domain
//   stream sockets, and Unix domain datagram sockets. The parseMessage() function
//   from parser.go strips RFC 3164 / RFC 5424 envelopes before forwarding the
//   embedded log line to the configured LineParser.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): emits *plugin.Event with parser-owned
//   LogEntry as Payload (built via WrapLogEntry).

package syslog

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

// SyslogSource listens for syslog messages over network transports and delivers
// parsed *plugin.Event values to the pipeline.
type SyslogSource struct {
	name    string
	network string
	host    string
	parser  pkgsource.LineParser
	logFn   func(tag, msg, level string)

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
	maxConns    int
}

const defaultMaxConns = 1000

func New(addr string, parser pkgsource.LineParser, logFn func(string, string, string), maxConnections int) (*SyslogSource, error) {
	network, host, err := parseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("syslog source: %w", err)
	}
	if parser == nil {
		return nil, fmt.Errorf("syslog source %s: parser must not be nil", addr)
	}
	maxConns := maxConnections
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	return &SyslogSource{
		name:     "syslog:" + addr,
		network:  network,
		host:     host,
		parser:   parser,
		logFn:    logFn,
		maxConns: maxConns,
	}, nil
}

func parseAddr(addr string) (network, host string, err error) {
	scheme, rest, ok := strings.Cut(addr, "://")
	if !ok || scheme == "" || rest == "" {
		return "", "", fmt.Errorf("invalid syslog address %q: expected scheme://host", addr)
	}
	switch scheme {
	case "udp":
		return "udp", rest, nil
	case "tcp":
		return "tcp", rest, nil
	case "unix":
		return "unix", rest, nil
	case "unixgram":
		return "unixgram", rest, nil
	default:
		return "", "", fmt.Errorf("unknown syslog scheme %q in address %q", scheme, addr)
	}
}

func (s *SyslogSource) Name() string { return s.name }

func (s *SyslogSource) Close() error { return nil }

func (s *SyslogSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

func (s *SyslogSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "syslog",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"syslog", "udp", "tcp", "unix", "rfc3164", "rfc5424", "network"},
		// Produces declares the Envelope fields this source guarantees to populate.
		// Payload fields (Line, ...) are filled downstream by the parser and are NOT
		// declared here — the source only owns the transport envelope (Flow 083 P1).
		// Stream is filled by the engine from EventContext before downstream consumers
		// observe the Event; Level is filled later by the product scorer, so neither
		// is set at Wrap time but both are guaranteed by the time the Event flows on.
		Produces: []plugin.FieldDecl{
			{Name: "Timestamp", Required: true},
			{Name: "Stream", Required: true},
			{Name: "Source", Required: true},
			{Name: "SourceType", Required: true},
		},
	}
}

func (s *SyslogSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	if s.network == "udp" || s.network == "unixgram" {
		return s.runPacket(ctx, out)
	}
	return s.runStream(ctx, out)
}

func (s *SyslogSource) runPacket(ctx context.Context, out chan<- *plugin.Event) error {
	conn, err := net.ListenPacket(s.network, s.host)
	if err != nil {
		return fmt.Errorf("syslog source: listen packet on %s://%s: %w", s.network, s.host, err)
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if n == len(buf) && s.logFn != nil {
			s.logFn("SYSLOG", fmt.Sprintf("UDP datagram may be truncated (buffer %d bytes full) on %s", len(buf), s.host), "warning")
		}
		s.linesRead.Add(1)
		line, err := parseMessage(buf[:n])
		if err != nil {
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SYSLOG", fmt.Sprintf("parse envelope error: %v", err), "debug")
			}
			continue
		}
		entry, ok := s.parser.Parse(line)
		if !ok {
			s.parseErrors.Add(1)
			continue
		}
		ev := parser.WrapLogEntry(entry, plugin.Envelope{
			Source:     s.name,
			SourceType: "syslog",
			Stream:     "",
			Timestamp:  entry.Time,
			Level:      "",
		})
		select {
		case out <- ev:
		default:
			s.dropped.Add(1)
		}
	}
	return nil
}

func (s *SyslogSource) runStream(ctx context.Context, out chan<- *plugin.Event) error {
	l, err := net.Listen(s.network, s.host)
	if err != nil {
		return fmt.Errorf("syslog source: listen stream on %s://%s: %w", s.network, s.host, err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	maxConns := s.maxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	sem := make(chan struct{}, maxConns)

	var wg sync.WaitGroup
acceptLoop:
	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			break acceptLoop
		}
		wg.Add(1)
		go s.handleConn(ctx, conn, out, &wg, sem)
	}
	wg.Wait()
	return nil
}

func (s *SyslogSource) handleConn(ctx context.Context, conn net.Conn, out chan<- *plugin.Event, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	defer conn.Close()
	if sem != nil {
		defer func() { <-sem }()
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 65536), 65536)
	for sc.Scan() {
		s.linesRead.Add(1)
		line, err := parseMessage(sc.Bytes())
		if err != nil {
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SYSLOG", fmt.Sprintf("parse envelope error: %v", err), "debug")
			}
			continue
		}
		entry, ok := s.parser.Parse(line)
		if !ok {
			s.parseErrors.Add(1)
			continue
		}
		ev := parser.WrapLogEntry(entry, plugin.Envelope{
			Source:     s.name,
			SourceType: "syslog",
			Stream:     "",
			Timestamp:  entry.Time,
			Level:      "",
		})
		select {
		case out <- ev:
		default:
			s.dropped.Add(1)
		}
	}
	if err := sc.Err(); err != nil {
		s.parseErrors.Add(1)
		if s.logFn != nil {
			s.logFn("SYSLOG", fmt.Sprintf("TCP scanner error on %s: %v", s.host, err), "error")
		}
	}
}

func init() {
	pkgsource.Register("syslog", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return New(cfg.Addr, opts.Parser, opts.LogFn, cfg.MaxConnections)
	})
	pkgsource.RegisterManifest("syslog", (&SyslogSource{}).Manifest())
}