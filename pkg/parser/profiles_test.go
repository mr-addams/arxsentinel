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
	// Traefik with accessLog and fields.headers.names.User-Agent/Referer: keep.
	// The format is Combined Log Format — UA and Referer are populated, not "-".
	p, err := traefikProfile()
	if err != nil {
		t.Fatalf("traefikProfile: %v", err)
	}

	line := `192.168.100.5 - alice [20/Apr/2023:08:00:00 +0000] "POST /api/login HTTP/1.1" 200 250 "http://example.com/" "Mozilla/5.0"`
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
	if e.BytesSent != 250 {
		t.Errorf("BytesSent: want 250, got %d", e.BytesSent)
	}
	if e.Referer != "http://example.com/" {
		t.Errorf("Referer: want http://example.com/, got %q", e.Referer)
	}
	if e.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent: want Mozilla/5.0, got %q", e.UserAgent)
	}
	if e.Time.IsZero() {
		t.Error("Time: want non-zero")
	}
}

func TestTraefikProfile_ExtraTrailingFields(t *testing.T) {
	// Traefik CLF format appends extra fields (duration, router, service, retries).
	// Pattern has no end anchor — extra fields must be silently ignored.
	// Real log line from Traefik container in integration tests.
	p, err := traefikProfile()
	if err != nil {
		t.Fatalf("traefikProfile: %v", err)
	}

	line := `172.18.0.1 - - [20/May/2026:16:24:34 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "http://evil.com" "AhrefsBot/7.0" 1 "default@file" "http://nginx:80" 8ms`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("traefik trailing fields: expected parse success, got false")
	}
	if e.RemoteAddr != "172.18.0.1" {
		t.Errorf("RemoteAddr: want 172.18.0.1, got %q", e.RemoteAddr)
	}
	if e.Status != 404 {
		t.Errorf("Status: want 404, got %d", e.Status)
	}
	if e.Path != "/wp-login.php" {
		t.Errorf("Path: want /wp-login.php, got %q", e.Path)
	}
	if e.Referer != "http://evil.com" {
		t.Errorf("Referer: want http://evil.com, got %q", e.Referer)
	}
	if e.UserAgent != "AhrefsBot/7.0" {
		t.Errorf("UserAgent: want AhrefsBot/7.0, got %q", e.UserAgent)
	}
}

// ========================== haproxy-http ============================================

func TestHAProxyHTTPProfile_HTTPLogLine(t *testing.T) {
	// HAProxy log-format with captured User-Agent appended — real line from integration container.
	// Produced by: http-request capture req.hdr(user-agent) len 200
	//              log-format "... %{+Q}r \"%[capture.req.hdr(0)]\""
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	line := `172.18.0.1:58186 [20/May/2026:16:24:34 +0000] http-in nginx-backend/nginx 0/0/0/0/0 200 506 - - ---- 1/1/0/0/0 0/0 "GET /dashboard HTTP/1.1" "AhrefsBot/7.0"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("haproxy: expected parse success, got false")
	}

	if e.RemoteAddr != "172.18.0.1" {
		t.Errorf("RemoteAddr: want 172.18.0.1, got %q", e.RemoteAddr)
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
	if e.BytesSent != 506 {
		t.Errorf("BytesSent: want 506, got %d", e.BytesSent)
	}
	if e.UserAgent != "AhrefsBot/7.0" {
		t.Errorf("UserAgent: want AhrefsBot/7.0, got %q", e.UserAgent)
	}
	if e.Time.IsZero() {
		t.Error("Time: want non-zero")
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

func TestHAProxyHTTPProfile_WithUserAgent(t *testing.T) {
	// HAProxy log-format with captured User-Agent appended after the request field.
	// Produced by: http-request capture req.hdr(user-agent) len 200
	//              log-format "... %{+Q}r \"%[capture.req.hdr(0)]\""
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	line := `10.20.30.40:54321 [05/Mar/2024:14:30:00.123] http-in~ be_web/web01 0/0/2/8/10 200 3456 - - ---- 7/6/0/1/0 0/0 "GET /dashboard HTTP/2.0" "AhrefsBot/7.0"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("haproxy with UA: expected parse success, got false")
	}
	if e.RemoteAddr != "10.20.30.40" {
		t.Errorf("RemoteAddr: want 10.20.30.40, got %q", e.RemoteAddr)
	}
	if e.UserAgent != "AhrefsBot/7.0" {
		t.Errorf("UserAgent: want AhrefsBot/7.0, got %q", e.UserAgent)
	}
}

func TestHAProxyHTTPProfile_WithoutUserAgent(t *testing.T) {
	// Old-style HAProxy log without UA field — optional group must be absent, not fail.
	p, err := haproxyHTTPProfile()
	if err != nil {
		t.Fatalf("haproxyHTTPProfile: %v", err)
	}

	line := `10.20.30.40:54321 [05/Mar/2024:14:30:00.123] http-in~ be_web/web01 0/0/2/8/10 200 3456 - - ---- 7/6/0/1/0 0/0 "GET /dashboard HTTP/2.0"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("haproxy without UA: expected parse success, got false")
	}
	if e.UserAgent != "" {
		t.Errorf("UserAgent: want empty string, got %q", e.UserAgent)
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

// ========================== litespeed ===============================================

func TestLiteSpeedProfile_CombinedLine(t *testing.T) {
	// Standard OLS / LSWS CLF line — format is byte-identical to Apache CLF.
	p, err := litespeedProfile()
	if err != nil {
		t.Fatalf("litespeedProfile: %v", err)
	}

	line := `203.0.113.42 - - [19/May/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 4096 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("litespeed: expected parse success, got false")
	}

	if e.RemoteAddr != "203.0.113.42" {
		t.Errorf("RemoteAddr: want 203.0.113.42, got %q", e.RemoteAddr)
	}
	// No real_ip field in CLF — RealIP falls back to RemoteAddr.
	if e.RealIP != "203.0.113.42" {
		t.Errorf("RealIP: want 203.0.113.42, got %q", e.RealIP)
	}
	if e.Method != "GET" {
		t.Errorf("Method: want GET, got %q", e.Method)
	}
	if e.Path != "/index.html" {
		t.Errorf("Path: want /index.html, got %q", e.Path)
	}
	if e.Status != 200 {
		t.Errorf("Status: want 200, got %d", e.Status)
	}
	if e.BytesSent != 4096 {
		t.Errorf("BytesSent: want 4096, got %d", e.BytesSent)
	}
	if e.Referer != "https://example.com/" {
		t.Errorf("Referer: want https://example.com/, got %q", e.Referer)
	}
	if e.Time.IsZero() {
		t.Error("Time: want non-zero")
	}
}

func TestLiteSpeedProfile_BytesDash(t *testing.T) {
	// OLS logs bytes_sent as "-" for HEAD and 304 responses, same as Apache.
	p, err := litespeedProfile()
	if err != nil {
		t.Fatalf("litespeedProfile: %v", err)
	}

	line := `198.51.100.7 - - [19/May/2026:11:00:00 +0000] "HEAD /favicon.ico HTTP/1.1" 200 -`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("litespeed bytes_dash: expected parse success, got false")
	}
	if e.BytesSent != 0 {
		t.Errorf("BytesSent: want 0 (from '-'), got %d", e.BytesSent)
	}
}

func TestLiteSpeedProfile_ProxyRealIP(t *testing.T) {
	// When UseIpInProxyHeader is enabled, OLS substitutes the real client IP
	// into %h directly. The CLF line already contains the client IP — no extra
	// real_ip field. RealIP == RemoteAddr is the expected result.
	p, err := litespeedProfile()
	if err != nil {
		t.Fatalf("litespeedProfile: %v", err)
	}

	// 185.220.101.5 is the real attacker; 10.0.0.1 is the proxy — but OLS has
	// already replaced %h with the XFF value, so the log shows the real IP.
	line := `185.220.101.5 - - [19/May/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 196 "-" "python-requests/2.28"`
	e, ok := p.Parse(line)
	if !ok {
		t.Fatal("litespeed proxy real ip: expected parse success, got false")
	}
	if e.RemoteAddr != "185.220.101.5" {
		t.Errorf("RemoteAddr: want 185.220.101.5, got %q", e.RemoteAddr)
	}
	if e.RealIP != "185.220.101.5" {
		t.Errorf("RealIP: want 185.220.101.5, got %q", e.RealIP)
	}
}

func TestLiteSpeedProfile_InvalidLine(t *testing.T) {
	p, err := litespeedProfile()
	if err != nil {
		t.Fatalf("litespeedProfile: %v", err)
	}

	_, ok := p.Parse("not a litespeed log line at all")
	if ok {
		t.Error("litespeed invalid: expected false, got true")
	}
}

// ========================== Profiles map ============================================

func TestProfilesMap_AllKnown(t *testing.T) {
	// All expected profiles must be present and constructible without error.
	expected := []string{"apache", "caddy", "traefik", "haproxy-http", "litespeed"}
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

func TestAvailableProfiles_ContainsAllKnown(t *testing.T) {
	available := AvailableProfiles()
	parts := strings.Split(available, ", ")
	idx := make(map[string]bool, len(parts))
	for _, p := range parts {
		idx[p] = true
	}
	for _, name := range []string{"apache", "caddy", "haproxy-http", "litespeed", "traefik"} {
		if !idx[name] {
			t.Errorf("AvailableProfiles: %q not found in %q", name, available)
		}
	}
}
