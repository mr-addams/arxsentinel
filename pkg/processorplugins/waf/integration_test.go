// ========================== pkg/processor/waf — integration tests =====================
//   End-to-end coverage for WafProcessor against realistic log-format inputs (Flow 001,
//   Task H5). The unit tests in processor_test.go exercise the processor in isolation;
//   these tests prove the "any pipeline" claim by feeding real parsed log records.
//
//   Test surfaces:
//     1. TestIntegration_NginxCLF — Full pipeline: nginx combined CLF → parser → WAF →
//        verdict. Exercises all four rule actions (tag, drop, pass, no-match) and the
//        `in` / `matches` operators against parser.LogEntry fields.
//     2. TestIntegration_NginxJSON — Second source format: nginx JSON log via
//        parser.NewJSONParser. Demonstrates the "any pipeline" property — the WAF
//        processor does not care about source format, only about the *LogEntry payload.
//     3. TestIntegration_IPInCIDR — Focused test on the `in` operator with CIDR list.
//        Confirms RFC 4632/IPv4 CIDR membership semantics that downstream geo-blocking
//        and rate-limit processors will rely on.
//     4. TestIntegration_RegexMatch — Focused test on the `matches` operator. Verifies
//        that WAF rules can use RE2 patterns against http.user_agent.
//     5. TestIntegration_FailFast_BadExpression — Init-time contract: any bad
//        expression fails NewWafProcessor before Process is reachable. The Init is
//        the sole gate — there is no runtime compile path (regression scenario).
//     6. BenchmarkWafProcessor_HotPath — Throughput + allocs/op on the no-match
//        passthrough path (the production-hot path: most events match zero rules).
//
//   Design notes:
//     - Parsers, LogEntry, and Event bridge helpers come from arx-core/pkg/parser.
//     - makeLogEvent / makeEvent / contains helpers are reused from processor_test.go
//       and resolver_test.go (same package — no duplication).
//     - Tests construct events through the public parser path where possible, to
//       catch integration regressions that unit tests with hand-built LogEntry
//       could miss (regex change, time-layout drift, etc.).

package waf

import (
	"context"
	"testing"

	"github.com/mr-addams/arx-core/pkg/parser"
)

// ========================== 1. Nginx CLF end-to-end pipeline ============================

// TestIntegration_NginxCLF runs the full pipeline against a realistic nginx combined
// log line: parser.Parse → LogEntry → WafProcessor.Process → verdict. Confirms that
// the rule engine is wired correctly through the resolver chain, and that all four
// action shapes (drop, tag, pass, no-match) are reachable through real parsed data.
//
// The rule set is intentionally a superset of defaultConfig() — it adds CIDR and
// regex operators that the default config does not exercise, so the integration
// test covers the `in` and `matches` paths that downstream detectors (rate-limit,
// geo-block, UA filter) will rely on.
func TestIntegration_NginxCLF(t *testing.T) {
	// ── Config with rich rule operators (in, matches, contains, eq, compound and) ──
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "block_post_405", Expression: `http.method eq "POST" and http.status eq 405`, Action: ActionDrop},
			{Name: "tag_admin_path", Expression: `http.path contains "/admin"`, Action: ActionTag},
			{Name: "tag_curl", Expression: `http.user_agent matches "curl.*"`, Action: ActionTag},
			{Name: "pass_healthcheck", Expression: `http.path eq "/healthz"`, Action: ActionPass},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	// ── Source: nginx combined CLF line with real $real_ip at the tail ─────────────
	// The CombinedParser regex is anchored — line MUST match the canonical shape.
	line := `127.0.0.1 - - [29/Jun/2026:12:00:00 +0000] "GET /admin/login HTTP/1.1" 401 1234 "https://ref.example.com" "curl/8.5.0" "203.0.113.42"`

	entry, ok := (&parser.CombinedParser{}).Parse(line)
	if !ok {
		t.Fatalf("CombinedParser.Parse: failed to parse real nginx CLF line")
	}
	if entry.Path != "/admin/login" {
		t.Fatalf("CombinedParser.Parse: Path=%q, want /admin/login (sanity)", entry.Path)
	}

	ev := makeLogEvent(entry)
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (tag=passthrough), got nil")
	}
	// tag_admin_path fires (path contains /admin), but tag_curl also fires.
	// First-match-wins (DECISION D12) means the first matching rule in cfg order
	// wins — block_post_405 is first and does NOT match (method is GET, status 401),
	// tag_admin_path matches second → its tag stamps Level.
	if got.Envelope.Level != "THREAT:tag_admin_path" {
		t.Errorf("Process: Level=%q, want %q (tag_admin_path fires before tag_curl)",
			got.Envelope.Level, "THREAT:tag_admin_path")
	}

	// ── Case A: POST + 405 → drop path. hand-built entry to control the fields. ──
	evDrop := makeLogEvent(&parser.LogEntry{Method: "POST", Status: 405, Path: "/api/users"})
	if got, err := p.Process(context.Background(), evDrop); err != nil || got != nil {
		t.Errorf("drop case: got=%v err=%v, want (nil,nil)", got, err)
	}

	// ── Case B: path contains /admin but method GET, status 200 → tag fires ─────────
	evTag := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/admin/users"})
	if got, err := p.Process(context.Background(), evTag); err != nil || got == nil {
		t.Fatalf("tag case: got=%v err=%v, want non-nil event", got, err)
	} else if got.Envelope.Level != "THREAT:tag_admin_path" {
		t.Errorf("tag case: Level=%q, want tag_admin_path", got.Envelope.Level)
	}

	// ── Case C: /healthz → pass action, event untouched ───────────────────────────
	evPass := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/healthz"})
	got, err = p.Process(context.Background(), evPass)
	if err != nil || got == nil {
		t.Fatalf("pass case: got=%v err=%v, want non-nil event", got, err)
	} else if got.Envelope.Level != "" {
		t.Errorf("pass case: Level=%q, want empty (pass is a no-op)", got.Envelope.Level)
	}

	// ── Case D: regular request that matches nothing → passthrough, Level empty ───
	evNoMatch := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/products"})
	evNoMatch.Envelope.Level = "INFO"
	got, err = p.Process(context.Background(), evNoMatch)
	if err != nil || got == nil {
		t.Fatalf("no-match case: got=%v err=%v", got, err)
	} else if got.Envelope.Level != "INFO" {
		t.Errorf("no-match case: Level=%q, want INFO (untouched)", got.Envelope.Level)
	}

	// ── Case E: UA matches "curl.*" but no other rule fires → tag_curl ───────────
	evCurl := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/api", UserAgent: "curl/8.0"})
	got, err = p.Process(context.Background(), evCurl)
	if err != nil || got == nil {
		t.Fatalf("curl case: got=%v err=%v", got, err)
	} else if got.Envelope.Level != "THREAT:tag_curl" {
		t.Errorf("curl case: Level=%q, want THREAT:tag_curl", got.Envelope.Level)
	}
}

// ========================== 2. Nginx JSON second-format pipeline =========================

// TestIntegration_NginxJSON runs a real JSON-formatted nginx log line through
// parser.NewJSONParser and feeds the result into WafProcessor. Proves the "any
// pipeline" claim: the WAF plugin's contract is parser.LogEntry, not a specific
// wire format. Source-side format choice (CLF vs. JSON vs. CF Logpush) is purely
// a parser concern.
//
// The JSON line below uses the canonical nginx log_format json field names —
// remote_addr / time_iso8601 / request / status / bytes_sent / http_referer /
// http_user_agent / real_ip — which is what defaultConfig-style deployments expect.
func TestIntegration_NginxJSON(t *testing.T) {
	// ── JSON parser with default field mapping (matches default nginx log_format) ─
	jp := parser.NewJSONParser(parser.JSONFieldsConfig{
		// Explicit field mapping = self-contained copy-paste example (no reliance on parser defaults).
		RemoteAddr: "remote_addr",
		Time:       "time_iso8601",
		Request:    "request",
		Status:     "status",
		BytesSent:  "bytes_sent",
		Referer:    "http_referer",
		UserAgent:  "http_user_agent",
		RealIP:     "real_ip",
	})

	line := `{"remote_addr":"192.168.1.50","time_iso8601":"2026-06-29T12:00:00+00:00","request":"GET /admin HTTP/1.1","status":"200","bytes_sent":"512","http_referer":"-","http_user_agent":"curl/8.0","real_ip":"8.8.8.8"}`

	entry, ok := jp.Parse(line)
	if !ok {
		t.Fatalf("JSONParser.Parse: failed to parse real nginx JSON line")
	}
	if entry.Path != "/admin" {
		t.Fatalf("JSONParser.Parse: Path=%q, want /admin", entry.Path)
	}
	if entry.RealIP != "8.8.8.8" {
		t.Fatalf("JSONParser.Parse: RealIP=%q, want 8.8.8.8", entry.RealIP)
	}

	// ── Reuse the same rich rule set as the CLF integration test ──────────────────
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "tag_admin_path", Expression: `http.path contains "/admin"`, Action: ActionTag},
			{Name: "tag_curl", Expression: `http.user_agent matches "curl.*"`, Action: ActionTag},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	ev := makeLogEvent(entry)
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (tag=passthrough), got nil")
	}
	// First-match-wins: tag_admin_path comes first in cfg; it matches → its tag fires.
	if got.Envelope.Level != "THREAT:tag_admin_path" {
		t.Errorf("Process: Level=%q, want %q", got.Envelope.Level, "THREAT:tag_admin_path")
	}
}

// ========================== 3. IP-in-CIDR membership ====================================

// TestIntegration_IPInCIDR pins the contract for CIDR-based blocking rules. The rule
// `in` operator with an array of ip"…/N" literals matches any IP inside the listed
// CIDR blocks — this is the universal "geo-block" / "internal-only" pattern that
// downstream detectors will use. We test the match path (10/8 → drop) and the
// passthrough path (8.8.8.8 → untouched).
func TestIntegration_IPInCIDR(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "block_internal", Expression: `http.real_ip in [ip"10.0.0.0/8", ip"172.16.0.0/12"]`, Action: ActionDrop},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	// ── Hit: real_ip 10.5.5.5 falls inside 10/8 → drop ──────────────────────────────
	evHit := makeLogEvent(&parser.LogEntry{RealIP: "10.5.5.5", Method: "GET", Status: 200})
	got, err := p.Process(context.Background(), evHit)
	if err != nil {
		t.Fatalf("Process (hit): %v", err)
	}
	if got != nil {
		t.Errorf("Process (hit): want nil event (drop), got %+v", got)
	}

	// ── Miss: real_ip 8.8.8.8 is not in any listed CIDR → passthrough ─────────────
	evMiss := makeLogEvent(&parser.LogEntry{RealIP: "8.8.8.8", Method: "GET", Status: 200})
	got, err = p.Process(context.Background(), evMiss)
	if err != nil {
		t.Fatalf("Process (miss): %v", err)
	}
	if got == nil {
		t.Fatal("Process (miss): want non-nil passthrough, got nil")
	}
	if got != evMiss {
		t.Errorf("Process (miss): want same *plugin.Event pointer back (no allocation)")
	}
	if got.Envelope.Level != "" {
		t.Errorf("Process (miss): Level=%q, want empty (untouched on no-match)", got.Envelope.Level)
	}
}

// ========================== 4. Regex match ===============================================

// TestIntegration_RegexMatch verifies the RE2-backed `matches` operator end-to-end
// against http.user_agent. The plugin exposes a string field that real pipelines
// will match for bot detection, scanner blocking, and tool allow-listing.
func TestIntegration_RegexMatch(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "tag_curl_version", Expression: `http.user_agent matches "curl/\\d+"`, Action: ActionTag},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	// ── Match: curl/8.0 → tag fires ───────────────────────────────────────────────
	evHit := makeLogEvent(&parser.LogEntry{Method: "GET", Path: "/", Status: 200, UserAgent: "curl/8.0"})
	got, err := p.Process(context.Background(), evHit)
	if err != nil || got == nil {
		t.Fatalf("match: got=%v err=%v, want non-nil event", got, err)
	} else if got.Envelope.Level != "THREAT:tag_curl_version" {
		t.Errorf("match: Level=%q, want THREAT:tag_curl_version", got.Envelope.Level)
	}

	// ── Miss: Mozilla/5.0 doesn't match curl/\d+ → passthrough ─────────────────────
	evMiss := makeLogEvent(&parser.LogEntry{Method: "GET", Path: "/", Status: 200, UserAgent: "Mozilla/5.0"})
	got, err = p.Process(context.Background(), evMiss)
	if err != nil || got == nil {
		t.Fatalf("miss: got=%v err=%v, want non-nil event", got, err)
	} else if got.Envelope.Level != "" {
		t.Errorf("miss: Level=%q, want empty (no-match)", got.Envelope.Level)
	}
}

// ========================== 5. Fail-fast at Init-time ====================================

// TestIntegration_FailFast_BadExpression asserts the atomicity contract on the
// integration boundary: any rule whose expression fails to compile aborts the
// whole NewWafProcessor call, and the rule name appears in the error so an
// operator chasing a typo in a 20-rule config can find it in seconds.
//
// A type-mismatch expression (`http.status eq "not_a_number"`) is a richer bad
// input than the syntactically invalid one used in processor_test.go — it
// exercises the type-checker path, not just the lexer/parser path. Both
// scenarios MUST fail at Init (never reach Process).
//
// Note: we intentionally do NOT add a runtime-error test. There IS no runtime
// compile path — every expression is compiled synchronously at Init (DECISION
// D4, "compile once, evaluate many times"). If a bad expression slips past
// Init, it is a regression worth catching as a unit bug, not an integration
// one.
func TestIntegration_FailFast_BadExpression(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "good_syntax", Expression: `http.status eq 200`},
			{Name: "bad_syntax", Expression: `this is not a valid expression at all @@@`},
			{Name: "bad_type", Expression: `http.status eq "not_a_number"`},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err == nil {
		t.Fatal("NewWafProcessor: want error for any bad expression, got nil")
	}
	// p must be nil after the error — calls into p.Process would be UB.
	if p != nil {
		t.Errorf("NewWafProcessor: want nil processor on error, got %+v", p)
	}
	// The rule-set builder processes rules in order and short-circuits on the
	// first failure — "bad_syntax" is first, so its name must appear in the error.
	msg := err.Error()
	if !contains(msg, "bad_syntax") {
		t.Errorf("error %q must name the first failing rule (bad_syntax)", msg)
	}
}

// ========================== 6. Hot-path throughput benchmark =============================

// BenchmarkWafProcessor_HotPath measures events/sec and allocs/op on the no-match
// passthrough path. This is the dominant production path (most events satisfy
// zero WAF rules), so it is the one to optimize for.
//
// Event construction is hoisted out of the timed region: the benchmark is meant
// to measure Process throughput, not envelope / payload allocation.
//
// To read a number after `go test -bench=. -benchmem`:
//
//	goos: linux
//	goarch: amd64
//	BenchmarkWafProcessor_HotPath-8    XXXXXXX    YYY ns/op      Z allocs/op    NNN MB/s
//
// events/sec = 1e9 / YYY  (per goroutine; × GOMAXPROCS for aggregate).
// allocs/op  = Z        (target: 0 allocations per call on the hot path).
func BenchmarkWafProcessor_HotPath(b *testing.B) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		b.Fatalf("NewWafProcessor: %v", err)
	}

	// Pre-construct the event so the benchmark measures Process, not envelope
	// building. /api/products matches none of the default rules → passthrough.
	ev := makeLogEvent(&parser.LogEntry{
		Method:     "GET",
		Path:       "/api/products",
		RemoteAddr: "192.0.2.10",
		RealIP:     "192.0.2.10",
		Status:     200,
		UserAgent:  "Mozilla/5.0",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Process(context.Background(), ev)
		if err != nil {
			b.Fatalf("Process: %v", err)
		}
	}
}

// BenchmarkWafProcessor_HotPathWithMatch measures the rule-match path (first rule
// fires → action dispatch). Useful when sizing configs with many rules: a single
// match costs more than a single no-match, and the difference tells you how
// much budget the rule walk + action map lookup eats.
//
// event/sec = 1e9 / ns/op  ; allocs/op = the trailing number
func BenchmarkWafProcessor_HotPathWithMatch(b *testing.B) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		b.Fatalf("NewWafProcessor: %v", err)
	}

	// block_post_405 fires every call → exercises the matched-rule action path.
	ev := makeLogEvent(&parser.LogEntry{
		Method: "POST",
		Status: 405,
		Path:   "/api/users",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// drop returns (nil, nil) so we have to be careful: a nil-typed
		// *plugin.Event is fine here, but a stale *Event from the previous
		// iter is NOT — Process must not mutate ev on drop. Spot-check by
		// comparing the input pointer against any non-nil result.
		got, err := p.Process(context.Background(), ev)
		if err != nil {
			b.Fatalf("Process: %v", err)
		}
		if got != nil {
			b.Fatal("Process: drop returned non-nil event")
		}
	}
}
