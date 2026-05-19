// ========================== Tests for built-in server profiles ===========================
//   Each test verifies a profile against a real access log line from that server.
//   Tests are written before the implementation (tests-first, project rule).

package parser

import (
	"strings"
	"testing"
)

// ========================== apache ==================================================

func TestApacheProfile_CombinedLine(t *testing.T) {
	p, err := apacheProfile()
	if err != nil {
		t.Fatalf("apacheProfile: %v", err)
	}

	line := `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("apache: expected parse success, got false")
	}

	if e.RemoteAddr != "127.0.0.1" {
		t.Errorf("RemoteAddr: want 127.0.0.1, got %q", e.RemoteAddr)
	}
	if e.RealIP != "127.0.0.1" {
		t.Errorf("RealIP: want 127.0.0.1, got %q", e.RealIP)
	}
	if e.Method != "GET" {
		t.Errorf("Method: want GET, got %q", e.Method)
	}
	if e.Path != "/apache_pb.gif" {
		t.Errorf("Path: want /apache_pb.gif, got %q", e.Path)
	}
	if e.Status != 200 {
		t.Errorf("Status: want 200, got %d", e.Status)
	}
	if e.BytesSent != 2326 {
		t.Errorf("BytesSent: want 2326, got %d", e.BytesSent)
	}
	if e.Referer != "http://www.example.com/start.html" {
		t.Errorf("Referer: want example.com, got %q", e.Referer)
	}
	if e.Time.IsZero() {
		t.Error("Time: want non-zero")
	}
}

func TestApacheProfile_BytesDash(t *testing.T) {
	// Apache logs bytes_sent as "-" for requests with no body (HEAD, 304, etc.).
	p, err := apacheProfile()
	if err != nil {
		t.Fatalf("apacheProfile: %v", err)
	}

	line := `10.0.0.1 - - [15/May/2023:12:00:00 +0000] "HEAD /health HTTP/1.1" 200 -`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("apache bytes_dash: expected parse success, got false")
	}
	if e.BytesSent != 0 {
		t.Errorf("BytesSent: want 0 (from '-'), got %d", e.BytesSent)
	}
}

func TestApacheProfile_InvalidLine(t *testing.T) {
	p, err := apacheProfile()
	if err != nil {
		t.Fatalf("apacheProfile: %v", err)
	}

	_, ok := p.Parse("not an apache log line at all")
	if ok {
		t.Error("apache invalid: expected false, got true")
	}
}

// ========================== caddy ===================================================

func TestCaddyProfile_CLFLine(t *testing.T) {
	// Caddy configured to output Apache CLF format via transform encoder.
	p, err := caddyProfile()
	if err != nil {
		t.Fatalf("caddyProfile: %v", err)
	}

	line := `172.16.0.1 - bob [12/Jun/2023:15:45:30 +0000] "GET /static/main.css HTTP/2.0" 200 18432 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("caddy: expected parse success, got false")
	}

	if e.RemoteAddr != "172.16.0.1" {
		t.Errorf("RemoteAddr: want 172.16.0.1, got %q", e.RemoteAddr)
	}
	if e.Path != "/static/main.css" {
		t.Errorf("Path: want /static/main.css, got %q", e.Path)
	}
	if e.Status != 200 {
		t.Errorf("Status: want 200, got %d", e.Status)
	}
}

// ========================== traefik =================================================

func TestTraefikProfile_CLFLine(t *testing.T) {
	// Traefik with accessLog (default common/CLF format).
	p, err := traefikProfile()
	if err != nil {
		t.Fatalf("traefikProfile: %v", err)
	}

	line := `192.168.100.5 - alice [20/Apr/2023:08:00:00 +0000] "POST /api/login HTTP/1.1" 200 250 "-" "Mozilla/5.0"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("traefik: expected parse success, got false")
	}

	if e.RemoteAddr != "192.168.100.5" {
		t.Errorf("RemoteAddr: want 192.168.100.5, got %q", e.RemoteAddr)
	}
	if e.Method != "POST" {
		t.Errorf("Method: want POST, got %q", e.Method)
	}
	if e.Path != "/api/login" {
		t.Errorf("Path: want /api/login, got %q", e.Path)
	}
	if e.Status != 200 {
		t.Errorf("Status: want 200, got %d", e.Status)
	}
}

func TestTraefikProfile_ExtraTrailingFields(t *testing.T) {
	// Traefik CLF format appends extra fields (duration, router, service, retries).
	// Pattern has no end anchor — extra fields must be silently ignored.
	p, err := traefikProfile()
	if err != nil {
		t.Fatalf("traefikProfile: %v", err)
	}

	// Traefik CLF with all extra fields appended
	line := `10.10.0.1 - - [15/Jul/2023:10:00:00 +0000] "GET / HTTP/1.1" 302 0 "-" "curl/7.52.1" 5432 "-" "frontend@docker" "backend@docker" 0`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("traefik trailing fields: expected parse success, got false")
	}
	if e.Status != 302 {
		t.Errorf("Status: want 302, got %d", e.Status)
	}
	if e.Path != "/" {
		t.Errorf("Path: want /, got %q", e.Path)
	}
}

// ========================== haproxy-http ============================================

func TestHAProxyHTTPProfile_HTTPLogLine(t *testing.T) {
	// HAProxy "option httplog" format without syslog prefix.
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	line := `10.20.30.40:54321 [05/Mar/2024:14:30:00.123] http-in~ be_web/web01 0/0/2/8/10 200 3456 - - ---- 7/6/0/1/0 0/0 "GET /dashboard HTTP/2.0"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("haproxy: expected parse success, got false")
	}

	if e.RemoteAddr != "10.20.30.40" {
		t.Errorf("RemoteAddr: want 10.20.30.40, got %q", e.RemoteAddr)
	}
	if e.Method != "GET" {
		t.Errorf("Method: want GET, got %q", e.Method)
	}
	if e.Path != "/dashboard" {
		t.Errorf("Path: want /dashboard, got %q", e.Path)
	}
	if e.Status != 200 {
		t.Errorf("Status: want 200, got %d", e.Status)
	}
	if e.BytesSent != 3456 {
		t.Errorf("BytesSent: want 3456, got %d", e.BytesSent)
	}
}

func TestHAProxyHTTPProfile_TimeWithMilliseconds(t *testing.T) {
	// HAProxy time format includes milliseconds (.000) without timezone.
	// haproxyTimeLayout ("02/Jan/2006:15:04:05.000") must parse it correctly
	// so the rate detector receives a non-zero timestamp.
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	line := `1.2.3.4:9999 [01/Jan/2024:00:00:00.000] fe~ be/srv 0/0/0/1/1 200 100 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("haproxy time: expected parse success, got false")
	}
	if e.Time.IsZero() {
		t.Error("Time: want parsed timestamp, got zero — haproxyTimeLayout fallback not working")
	}
	want := "2024-01-01 00:00:00 +0000 UTC"
	if got := e.Time.UTC().String(); got != want {
		t.Errorf("Time: want %q, got %q", want, got)
	}
}

func TestHAProxyHTTPProfile_InvalidLine(t *testing.T) {
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	_, ok := p.Parse("not a haproxy log line")
	if ok {
		t.Error("haproxy invalid: expected false, got true")
	}
}

// ========================== Profiles map ============================================

func TestProfilesMap_AllKnown(t *testing.T) {
	// All expected profiles must be present and constructible without error.
	expected := []string{"apache", "caddy", "traefik", "haproxy-http"}
	for _, name := range expected {
		factory, ok := Profiles[name]
		if !ok {
			t.Errorf("Profiles[%q]: not found", name)
			continue
		}
		if _, err := factory(); err != nil {
			t.Errorf("Profiles[%q](): %v", name, err)
		}
	}
}

func TestAvailableProfiles_ContainsAllFour(t *testing.T) {
	available := AvailableProfiles()
	parts := strings.Split(available, ", ")
	idx := make(map[string]bool, len(parts))
	for _, p := range parts {
		idx[p] = true
	}
	for _, name := range []string{"apache", "caddy", "haproxy-http", "traefik"} {
		if !idx[name] {
			t.Errorf("AvailableProfiles: %q not found in %q", name, available)
		}
	}
}
