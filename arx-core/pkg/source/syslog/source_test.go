// ========================== pkg/source/syslog — tests ==========================================
//   Tests: UDP, TCP, RFC5424, MalformedPacket, RealParser, ConcurrentTCP,
//          UnixSocket, DropCounter, ParseAddr, ContextCancel.

package syslog

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubParser always parses a line as a minimal LogEntry with RemoteAddr set to
// the first space-delimited token of the line.
type stubParser struct{}

func (stubParser) Parse(line string) (*parser.LogEntry, bool) {
	if line == "" {
		return nil, false
	}
	parts := strings.SplitN(line, " ", 2)
	return &parser.LogEntry{RemoteAddr: parts[0]}, true
}

func TestSyslogSource_UDP(t *testing.T) {
	const testPort = "15514"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		assert.Equal(t, "1.2.3.4", parser.UnwrapLogEntry(ev).RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from UDP syslog source")
	}
}

func TestSyslogSource_TCP(t *testing.T) {
	const testPort = "15515"
	addr := "tcp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"` + "\n"
	conn, err := net.Dial("tcp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		assert.Equal(t, "1.2.3.4", parser.UnwrapLogEntry(ev).RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from TCP syslog source")
	}
}

func TestSyslogSource_RFC5424(t *testing.T) {
	const testPort = "15516"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - - 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		assert.Equal(t, "1.2.3.4", parser.UnwrapLogEntry(ev).RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from RFC 5424 syslog source")
	}
}

func TestSyslogSource_MalformedPacket(t *testing.T) {
	const testPort = "15517"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("this is not syslog"))
	require.NoError(t, err)

	select {
	case <-out:
		t.Fatal("unexpected entry for malformed packet")
	case <-time.After(200 * time.Millisecond):
	}

	stats := src.Stats()
	assert.Equal(t, int64(1), stats.ParseErrors)
}

// TestSyslogSource_RealParser verifies the full pipeline: syslog envelope stripping +
// real CombinedParser. Checks that all LogEntry fields are populated correctly,
// not just RemoteAddr (which stubParser would accept even with a broken envelope).
func TestSyslogSource_RealParser(t *testing.T) {
	const testPort = "15520"
	src, err := New("udp://127.0.0.1:"+testPort, &parser.CombinedParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 4)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	// Real nginx combined+real_ip log line wrapped in RFC 3164 syslog envelope.
	// CombinedParser requires the trailing "$real_ip" field — omitting it causes rejection.
	// If parseMessage cuts one byte too many or too few, CombinedParser will reject it.
	syslogMsg := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - bob [03/Jun/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 612 "https://example.com/" "Mozilla/5.0" "1.2.3.4"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(syslogMsg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		entry := parser.UnwrapLogEntry(ev)
		assert.Equal(t, "1.2.3.4", entry.RemoteAddr)
		assert.Equal(t, "GET", entry.Method)
		assert.Equal(t, "/index.html", entry.Path)
		assert.Equal(t, 200, entry.Status)
		assert.Equal(t, int64(612), entry.BytesSent)
		assert.Equal(t, "https://example.com/", entry.Referer)
		assert.Contains(t, entry.UserAgent, "Mozilla/5.0")
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout: no entry received; parseErrors=%d", src.Stats().ParseErrors)
	}
}

// TestSyslogSource_ConcurrentTCP opens N TCP connections simultaneously, each sending
// M syslog lines, then verifies Stats().LinesRead == N*M with no races.
// Run with -race to detect data races in handleConn / atomic counters.
func TestSyslogSource_ConcurrentTCP(t *testing.T) {
	const (
		testPort     = "15519"
		connections  = 10
		linesPerConn = 20
	)

	src, err := New("tcp://127.0.0.1:"+testPort, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Buffer large enough to never block senders — we drain it separately.
	out := make(chan *plugin.Event, connections*linesPerConn+10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	var wg sync.WaitGroup
	for i := range connections {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", "127.0.0.1:"+testPort)
			if err != nil {
				t.Errorf("conn %d: dial: %v", id, err)
				return
			}
			defer conn.Close()
			for j := range linesPerConn {
				line := fmt.Sprintf("<134>Jun  3 12:00:00 host nginx: 10.0.%d.%d - - [03/Jun/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"\n", id, j)
				if _, err := fmt.Fprint(conn, line); err != nil {
					t.Errorf("conn %d write %d: %v", id, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// Drain until all expected entries arrive or timeout.
	total := connections * linesPerConn
	deadline := time.After(2 * time.Second)
	received := 0
	for received < total {
		select {
		case <-out:
			received++
		case <-deadline:
			t.Fatalf("timeout: got %d/%d entries; Stats=%+v", received, total, src.Stats())
		}
	}

	stats := src.Stats()
	assert.Equal(t, int64(total), stats.LinesRead, "LinesRead mismatch")
	assert.Equal(t, int64(0), stats.ParseErrors, "unexpected parse errors")
	assert.Equal(t, int64(0), stats.Dropped, "unexpected drops")
}

// TestSyslogSource_UnixSocket verifies the unixgram transport end-to-end.
// nginx on the same host typically uses unix sockets for zero-copy log shipping.
func TestSyslogSource_UnixSocket(t *testing.T) {
	sockPath := "/tmp/arxsentinel-syslog-test.sock"
	os.Remove(sockPath)
	defer os.Remove(sockPath)

	src, err := New("unixgram://"+sockPath, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 4)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>Jun  3 12:00:00 myhost nginx: 10.0.0.1 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`
	conn, err := net.Dial("unixgram", sockPath)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		assert.Equal(t, "10.0.0.1", parser.UnwrapLogEntry(ev).RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout: no entry from unix socket; parseErrors=%d", src.Stats().ParseErrors)
	}
}

// TestSyslogSource_RFC5424_RealParser verifies that RFC 5424 envelope stripping
// produces a line the real CombinedParser accepts with all fields intact.
func TestSyslogSource_RFC5424_RealParser(t *testing.T) {
	const testPort = "15521"
	src, err := New("udp://127.0.0.1:"+testPort, &parser.CombinedParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.Event, 4)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	// RFC 5424: VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
	// STRUCTURED-DATA="-" (nil); MSG is the nginx combined+real_ip line.
	syslogMsg := `<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - - 5.6.7.8 - alice [03/Jun/2026:12:00:00 +0000] "POST /api/login HTTP/2.0" 401 88 "-" "python-requests/2.31" "5.6.7.8"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(syslogMsg))
	require.NoError(t, err)

	select {
	case ev := <-out:
		entry := parser.UnwrapLogEntry(ev)
		assert.Equal(t, "5.6.7.8", entry.RemoteAddr)
		assert.Equal(t, "POST", entry.Method)
		assert.Equal(t, "/api/login", entry.Path)
		assert.Equal(t, 401, entry.Status)
		assert.Equal(t, int64(88), entry.BytesSent)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout: RFC 5424 + real parser; parseErrors=%d", src.Stats().ParseErrors)
	}
}

// TestSyslogSource_DropCounter verifies that entries are dropped and counted when
// the out channel is full. Ensures the drop path does not block or panic.
func TestSyslogSource_DropCounter(t *testing.T) {
	const testPort = "15522"
	src, err := New("udp://127.0.0.1:"+testPort, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capacity 0 — every send will be a drop.
	out := make(chan *plugin.Event, 0)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()

	const sends = 5
	msg := []byte(`<134>Jun  3 12:00:00 host nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`)
	for range sends {
		_, err = conn.Write(msg)
		require.NoError(t, err)
		time.Sleep(5 * time.Millisecond) // let each packet be processed before next
	}
	time.Sleep(50 * time.Millisecond)

	stats := src.Stats()
	assert.Equal(t, int64(sends), stats.LinesRead, "all packets received")
	assert.Equal(t, int64(sends), stats.Dropped, "all entries dropped (channel full)")
	assert.Equal(t, int64(0), stats.ParseErrors)
}

// TestParseAddr verifies the address parser for all supported schemes and rejects invalid input.
func TestParseAddr(t *testing.T) {
	cases := []struct {
		addr        string
		wantNetwork string
		wantHost    string
		wantErr     bool
	}{
		{"udp://0.0.0.0:5514", "udp", "0.0.0.0:5514", false},
		{"udp://:5514", "udp", ":5514", false},
		{"tcp://127.0.0.1:514", "tcp", "127.0.0.1:514", false},
		{"tcp://:514", "tcp", ":514", false},
		{"unix:///var/run/arx.sock", "unix", "/var/run/arx.sock", false},
		{"unixgram:///tmp/arx.sock", "unixgram", "/tmp/arx.sock", false},
		{"", "", "", true},
		{"http://localhost:80", "", "", true},
		{"udp://", "", "", true}, // empty host for non-unix
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			network, host, err := parseAddr(tc.addr)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantNetwork, network)
			assert.Equal(t, tc.wantHost, host)
		})
	}
}

func TestSyslogSource_ContextCancel(t *testing.T) {
	const testPort = "15518"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *plugin.Event, 1)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Run() did not return after ctx cancel within 200ms")
	}
}
