package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
	nethttp "net/http"
)

type testParser struct {
	parseFn func(line string) (*plugin.LogEntry, bool)
}

func (p *testParser) Parse(line string) (*plugin.LogEntry, bool) {
	return p.parseFn(line)
}

func testEntry(line string) (*plugin.LogEntry, bool) {
	return &plugin.LogEntry{RawURI: line}, true
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return fmt.Sprintf("%d", port)
}

func generateTLSCertFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = dir + "/cert.pem"
	keyFile = dir + "/key.pem"

	f, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	f, err = os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	f.Close()
	return
}

// ++++++++++++++++++++++++++ Fix 1: done-channel synchronisation +++++++++++++++++++++++++++++

func TestHTTPSourcePushPlain(t *testing.T) {
	port := freePort(t)
	addr := "http://127.0.0.1:" + port

	src, err := New(pkgsource.InputConfig{
		Addr:     addr,
		Protocol: "plain",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader([]byte("hello\nworld\n")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	entries := 0
	for len(out) > 0 {
		<-out
		entries++
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	if entries != 2 {
		t.Errorf("expected 2 entries, got %d", entries)
	}

	stats := src.Stats()
	if stats.LinesRead != 2 {
		t.Errorf("expected LinesRead=2, got %d", stats.LinesRead)
	}
}

func TestHTTPSourcePushHTTPS(t *testing.T) {
	certFile, keyFile := generateTLSCertFiles(t)
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "https://127.0.0.1:" + port,
		Protocol: "plain",
		TLSCert:  certFile,
		TLSKey:   keyFile,
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	client := &nethttp.Client{
		Transport: &nethttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Post("https://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader([]byte("test\n")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if stats.LinesRead != 1 {
		t.Errorf("expected LinesRead=1, got %d", stats.LinesRead)
	}
}

func TestHTTPSourceBearerAuth(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
		Token:    "secret123",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	// request without token
	req, _ := nethttp.NewRequest("POST", "http://127.0.0.1:"+port+"/", bytes.NewReader([]byte("x\n")))
	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// request with valid token
	req, _ = nethttp.NewRequest("POST", "http://127.0.0.1:"+port+"/", bytes.NewReader([]byte("x\n")))
	req.Header.Set("Authorization", "Bearer secret123")
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if stats.LinesRead != 1 {
		t.Errorf("expected LinesRead=1, got %d", stats.LinesRead)
	}
}

func TestHTTPSourceBodyLimit(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:         "http://127.0.0.1:" + port,
		Protocol:     "plain",
		MaxBodyBytes: 100,
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	// POST 101 bytes -> 413
	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader(bytes.Repeat([]byte("x"), 101)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}

	// POST 99 bytes -> 200
	resp, err = nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader(bytes.Repeat([]byte("x"), 99)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
}

// ++++++++++++++++++++++++++ Fix 2: remove vacuous assertion, add real parse-error case +++++++++++++++++++++++++++++

func TestHTTPSourceMalformedInput(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:          "http://127.0.0.1:" + port,
		Protocol:      "ndjson",
		EnvelopeField: "msg",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	// invalid JSON -> 400, server keeps running
	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "application/json", bytes.NewReader([]byte(`{invalid}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
}

func TestHTTPSourceMalformedInputParseError(t *testing.T) {
	port := freePort(t)

	failParser := &testParser{parseFn: func(line string) (*plugin.LogEntry, bool) {
		return nil, false
	}}

	src, err := New(pkgsource.InputConfig{
		Addr:          "http://127.0.0.1:" + port,
		Protocol:      "ndjson",
		EnvelopeField: "msg",
	}, failParser, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	// valid NDJSON but parser rejects the extracted line -> 200, ParseErrors incremented
	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "application/json",
		bytes.NewReader([]byte(`{"msg":"hello"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("expected ParseErrors=1, got %d", stats.ParseErrors)
	}
}

func TestHTTPSourceContextCancel(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Run() did not return within 300ms after context cancel")
	case err := <-done:
		if err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			t.Fatalf("Run() returned unexpected error: %v", err)
		}
	}
}

// ++++++++++++++++++++++++++ Fix 4: deterministic DropCounter +++++++++++++++++++++++++++++

func TestHTTPSourceDropCounter(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 2)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 5; i++ {
		resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader([]byte("line\n")))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if total := stats.LinesRead + stats.Dropped; total != 5 {
		t.Errorf("expected LinesRead + Dropped = 5, got %d (LinesRead=%d, Dropped=%d)", total, stats.LinesRead, stats.Dropped)
	}
	if stats.Dropped != 3 {
		t.Errorf("expected Dropped=3, got %d", stats.Dropped)
	}
}

func TestHTTPSourcePull(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/logs", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			nethttp.Error(w, "unauthorized", 401)
			return
		}
		w.Write([]byte("line1\nline2\n"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	server := &nethttp.Server{Addr: "127.0.0.1:" + fmt.Sprintf("%d", port), Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	src, err := New(pkgsource.InputConfig{
		Mode:         "pull",
		URL:          fmt.Sprintf("http://127.0.0.1:%d/logs", port),
		Protocol:     "plain",
		Token:        "tok",
		PullInterval: "50ms",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	time.Sleep(250 * time.Millisecond)
	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if stats.LinesRead == 0 {
		t.Error("expected LinesRead > 0 for pull mode")
	}
}

func TestHTTPSourceConcurrentPush(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader([]byte("line\n")))
			if err != nil {
				t.Logf("POST error: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	stats := src.Stats()
	if stats.LinesRead != 10 {
		t.Errorf("expected LinesRead=10, got %d", stats.LinesRead)
	}
}

func TestHTTPSourceRealParser(t *testing.T) {
	port := freePort(t)
	logLine := "20.48.232.178 - - [02/Apr/2026:00:26:49 +0000] \"GET / HTTP/2.0\" 200 66088 \"-\" \"-\" \"20.48.232.178\""

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
	}, &parser.CombinedParser{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 10)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "text/plain", bytes.NewReader([]byte(logLine+"\n")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	select {
	case entry := <-out:
		if entry.Status != 200 {
			t.Errorf("expected Status=200, got %d", entry.Status)
		}
		if entry.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", entry.Method)
		}
	default:
		t.Fatal("expected at least one parsed entry")
	}
}

// ++++++++++++++++++++++++++ Fix 5: gzip integration test +++++++++++++++++++++++++++++

func TestHTTPSourcePushGzip(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "plain",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("line1\nline2\nline3\n"))
	gw.Close()

	req, err := nethttp.NewRequest("POST", "http://127.0.0.1:"+port+"/", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	entries := 0
	for len(out) > 0 {
		<-out
		entries++
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	if entries != 3 {
		t.Errorf("expected 3 entries, got %d", entries)
	}

	stats := src.Stats()
	if stats.LinesRead != 3 {
		t.Errorf("expected LinesRead=3, got %d", stats.LinesRead)
	}
}

// ++++++++++++++++++++++++++ Fix 6: 415 rejection and PubSub JWT wiring +++++++++++++++++++++++++++++

func TestHTTPSourceProtobufRejected(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "loki",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	req, err := nethttp.NewRequest("POST", "http://127.0.0.1:"+port+"/", bytes.NewReader([]byte("some protobuf data")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 415 {
		t.Fatalf("expected 415, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
}

func TestHTTPSourcePubSubJWTRequired(t *testing.T) {
	port := freePort(t)

	src, err := New(pkgsource.InputConfig{
		Addr:     "http://127.0.0.1:" + port,
		Protocol: "pubsub",
	}, &testParser{parseFn: testEntry}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *plugin.LogEntry, 100)

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	time.Sleep(50 * time.Millisecond)

	// no Authorization header -> 401
	resp, err := nethttp.Post("http://127.0.0.1:"+port+"/", "application/json",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 with no auth, got %d", resp.StatusCode)
	}

	// valid-format Bearer token but wrong content -> 401
	req, err := nethttp.NewRequest("POST", "http://127.0.0.1:"+port+"/",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer some.random.token")
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 with invalid token, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
}
