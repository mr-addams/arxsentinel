// ========================== pkg/source/syslog — syslog network source =====================
//   Implements a Source that listens for syslog messages over UDP, TCP, Unix domain
//   stream sockets, and Unix domain datagram sockets. The parseMessage() function
//   from parser.go strips RFC 3164 / RFC 5424 envelopes before forwarding the
//   embedded log line to the configured LineParser.
//
//   WHAT IS HERE:
//     - SyslogSource struct — network listener with atomic counters
//     - New() constructor
//     - Run() dispatcher → runPacket() (UDP/unixgram) / runStream() (TCP/unix)
//     - Name(), Close(), Stats(), Manifest() — Source interface
//     - init() — registers factory and manifest in pkg/source
//
//   WHAT IS NOT HERE:
//     - parseMessage() — lives in parser.go (same package)
//     - RFC 3164 / RFC 5424 format details — see parser.go

package syslog

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

// SyslogSource listens for syslog messages over network transports and delivers
// parsed LogEntry values to the pipeline.
type SyslogSource struct {
	name    string
	network string               // "udp", "tcp", "unixgram", "unix"
	host    string               // ":5514" or "/var/run/arx.sock"
	parser  pkgsource.LineParser // parses extracted log line into *plugin.LogEntry
	logFn   func(tag, msg, level string)

	linesRead   atomic.Int64 // total messages received
	parseErrors atomic.Int64 // messages that failed to parse
	dropped     atomic.Int64 // entries dropped due to full channel buffer
	maxConns    int          // max simultaneous TCP connections (H5); 0 = unlimited (default 1000 from config)
}

// defaultMaxConns используется как значение по умолчанию, пока конфигурация
// не будет подключена через Task 2.6 (ARXSENTINEL_SYSLOG_MAX_CONNECTIONS).
const defaultMaxConns = 1000

// New creates a SyslogSource. addr is a URI-like string parsed by parseAddr:
//
//	"udp://:5514", "tcp://:514", "unix:///var/run/arx.sock",
//	"unixgram:///var/run/arx.sock"
//
// maxConnections limits concurrent TCP connections (0 = defaultMaxConns).
//
// Called from: pkg/source registry (init() → Build).
// Non-blocking — returns immediately with a configured instance or error.
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

// parseAddr splits an address URI into network and host components.
// Package-private helper used by New.
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

// Name returns the human-readable identifier for this source.
func (s *SyslogSource) Name() string { return s.name }

// Close releases resources. No-op for SyslogSource — the listener is closed
// by the context-driven goroutine in Run.
func (s *SyslogSource) Close() error { return nil }

// Stats returns a point-in-time snapshot of operational counters.
func (s *SyslogSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Manifest returns plugin metadata for the pipeline framework.
func (s *SyslogSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "syslog",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"syslog", "udp", "tcp", "unix", "rfc3164", "rfc5424", "network"},
	}
}

// Run dispatches to runPacket or runStream based on the transport type.
func (s *SyslogSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	if s.network == "udp" || s.network == "unixgram" {
		return s.runPacket(ctx, out)
	}
	return s.runStream(ctx, out)
}

// runPacket handles datagram-oriented transports (UDP, unixgram).
func (s *SyslogSource) runPacket(ctx context.Context, out chan<- *plugin.LogEntry) error {
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
		// L3: UDP truncation detection — если дейтаграмма заполнила буфер целиком,
		// возможно сообщение было обрезано. Логируем предупреждение о возможной потере.
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
		select {
		case out <- entry:
		default:
			s.dropped.Add(1)
		}
	}
	return nil
}

// runStream handles stream-oriented transports (TCP, unix socket).
func (s *SyslogSource) runStream(ctx context.Context, out chan<- *plugin.LogEntry) error {
	l, err := net.Listen(s.network, s.host)
	if err != nil {
		return fmt.Errorf("syslog source: listen stream on %s://%s: %w", s.network, s.host, err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	// H5: semaphore для ограничения одновременных TCP-соединений (maxConns).
	// Защита от resource exhaustion при лавине подключений.
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
		// H5: ждём свободный слот семафора, не блокируя Accept.
		// При контекстной отмене закрываем соединение и выходим.
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

// handleConn reads lines from a single TCP/unix connection until EOF or context
// cancellation.
func (s *SyslogSource) handleConn(ctx context.Context, conn net.Conn, out chan<- *plugin.LogEntry, wg *sync.WaitGroup, sem chan struct{}) {
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
		select {
		case out <- entry:
		default:
			s.dropped.Add(1)
		}
	}
	// H6: проверяем ошибку сканера после выхода из цикла Scan.
	// Если сканер упал по причине, отличной от EOF, логируем и считаем parse error.
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
