package syslog

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubParser always parses a line as a minimal LogEntry with RemoteAddr set to
// the first space-delimited token of the line.
type stubParser struct{}

func (stubParser) Parse(line string) (*plugin.LogEntry, bool) {
	if line == "" {
		return nil, false
	}
	parts := strings.SplitN(line, " ", 2)
	return &plugin.LogEntry{RemoteAddr: parts[0]}, true
}

func TestSyslogSource_UDP(t *testing.T) {
	const testPort = "15514"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.LogEntry, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case entry := <-out:
		assert.Equal(t, "1.2.3.4", entry.RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from UDP syslog source")
	}
}

func TestSyslogSource_TCP(t *testing.T) {
	const testPort = "15515"
	addr := "tcp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.LogEntry, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"` + "\n"
	conn, err := net.Dial("tcp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case entry := <-out:
		assert.Equal(t, "1.2.3.4", entry.RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from TCP syslog source")
	}
}

func TestSyslogSource_RFC5424(t *testing.T) {
	const testPort = "15516"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.LogEntry, 10)
	go func() { _ = src.Run(ctx, out) }()
	time.Sleep(20 * time.Millisecond)

	msg := `<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - - 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	conn, err := net.Dial("udp", "127.0.0.1:"+testPort)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	select {
	case entry := <-out:
		assert.Equal(t, "1.2.3.4", entry.RemoteAddr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: no entry received from RFC 5424 syslog source")
	}
}

func TestSyslogSource_MalformedPacket(t *testing.T) {
	const testPort = "15517"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan *plugin.LogEntry, 10)
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

func TestSyslogSource_ContextCancel(t *testing.T) {
	const testPort = "15518"
	addr := "udp://127.0.0.1:" + testPort
	src, err := New(addr, stubParser{}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *plugin.LogEntry, 1)

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