// ========================== pkg/processor/waf — resolver tests =========================
//   Table-driven coverage for HttpResolver (Flow 001, Task H2).
//
//   Coverage goals:
//     1. *parser.LogEntry happy path — every declared http.* field returns the
//        expected typed rule.Value.
//     2. nil event — never panics, returns (Value{}, false) for any http.* field.
//     3. Wrong namespace — `core.*` / non-namespaced / unknown http.<field> return
//        (Value{}, false).
//     4. IP failure modes — empty string, malformed IP, CIDR literal all return
//        (Value{}, false) for ip-typed fields.
//     5. *threat.ThreatEvent — only http.real_ip is answerable; other http.*
//        fields return (Value{}, false).
//     6. Other payload shapes — strings, ints, nil Payload all return (Value{},
//        false) without panic.

package waf

import (
	"net"
	"testing"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arxsentinel/internal/threat"
)

// ========================== helpers ========================================================

// makeEvent wraps payload into a *plugin.Event with a minimal Envelope. Tests that
// care about Envelope fields set them via the returned pointer.
func makeEvent(payload any) *plugin.Event {
	return &plugin.Event{
		Envelope: plugin.Envelope{
			Stream: "main",
			Source: "test",
		},
		Payload: payload,
	}
}

// ========================== 1. *parser.LogEntry happy path =================================

// TestHttpResolver_LogEntry exercises every Manifest.Produces field against a fully
// populated LogEntry. The pattern: one sub-test per field, table-driven to keep the
// assertion logic uniform and the failure messages targeted at the offending field.
//
// Field names are the FLATTENED form (Manifest convention — D7 forbids dots in the
// unqualified name). The resolver maps each flattened name to a typed LogEntry field;
// see resolveHTTP for the table.
func TestHttpResolver_LogEntry(t *testing.T) {
	entry := &parser.LogEntry{
		Method:     "POST",
		Path:       "/login",
		Query:      "u=admin",
		RawURI:     "/login?u=admin",
		Status:     401,
		BytesSent:  1234,
		Referer:    "https://example.com/",
		UserAgent:  "curl/8.5.0",
		RemoteAddr: "10.0.0.5",
		RealIP:     "203.0.113.42",
		Protocol:   "HTTP/1.1",
		RemoteUser: "alice",
	}
	ev := makeEvent(entry)
	r := HttpResolver{}

	cases := []struct {
		field string
		want  rule.Value
	}{
		{"http.method", rule.NewString("POST")},
		{"http.path", rule.NewString("/login")},
		{"http.query", rule.NewString("u=admin")},
		{"http.raw_uri", rule.NewString("/login?u=admin")},
		{"http.status", rule.NewInt(401)},
		{"http.bytes_sent", rule.NewInt(1234)},
		{"http.referer", rule.NewString("https://example.com/")},
		{"http.user_agent", rule.NewString("curl/8.5.0")},
		{"http.protocol", rule.NewString("HTTP/1.1")},
		{"http.remote_user", rule.NewString("alice")},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			got, ok := r.Resolve(tc.field, ev)
			if !ok {
				t.Fatalf("Resolve(%q): want ok=true, got false", tc.field)
			}
			if !got.Equal(tc.want) {
				t.Errorf("Resolve(%q): want %s, got %s", tc.field, tc.want, got)
			}
		})
	}
}

// TestHttpResolver_LogEntry_IP covers the two ip-typed fields separately because the
// equality check on KindIP wraps net.IP.Equal which normalises 4- vs 16-byte forms —
// verifying the expected IP via net.ParseIP keeps the table consistent with the
// implementation.
func TestHttpResolver_LogEntry_IP(t *testing.T) {
	entry := &parser.LogEntry{
		RemoteAddr: "10.0.0.5",
		RealIP:     "203.0.113.42",
	}
	ev := makeEvent(entry)
	r := HttpResolver{}

	cases := []struct {
		field string
		want  net.IP
	}{
		{"http.remote_addr", net.ParseIP("10.0.0.5")},
		{"http.real_ip", net.ParseIP("203.0.113.42")},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			got, ok := r.Resolve(tc.field, ev)
			if !ok {
				t.Fatalf("Resolve(%q): want ok=true, got false", tc.field)
			}
			ip, ok := got.AsIP()
			if !ok {
				t.Fatalf("Resolve(%q): kind=%s, want IP", tc.field, got.Kind())
			}
			if !ip.Equal(tc.want) {
				t.Errorf("Resolve(%q): want %s, got %s", tc.field, tc.want, ip)
			}
		})
	}
}

// ========================== 2. nil event ====================================================

// TestHttpResolver_NilEvent asserts the FieldResolver contract: a nil event is a
// sentinel, never a panic. Same guarantee EnvelopeResolver provides (pkg/rule).
func TestHttpResolver_NilEvent(t *testing.T) {
	r := HttpResolver{}
	for _, field := range []string{
		"http.method", "http.status", "http.real_ip", "http.path",
	} {
		t.Run(field, func(t *testing.T) {
			got, ok := r.Resolve(field, nil)
			if ok {
				t.Errorf("Resolve(%q, nil): want ok=false, got true", field)
			}
			if !got.IsZero() {
				t.Errorf("Resolve(%q, nil): want zero Value, got %s", field, got)
			}
		})
	}
}

// ========================== 3. Wrong namespace / unknown field ==============================

// TestHttpResolver_NamespaceAndUnknown asserts the dispatch chain is well-behaved:
// unknown namespaces, malformed (no-dot) names, and unknown http.<field> all surface
// as (Value{}, false) so the chain can fall through to the next resolver.
func TestHttpResolver_NamespaceAndUnknown(t *testing.T) {
	ev := makeEvent(&parser.LogEntry{Method: "GET"})
	r := HttpResolver{}

	fields := []string{
		// Other namespaces — EnvelopeResolver's job, not ours.
		"core.timestamp",
		"core.level",
		"syslog.message",
		// Malformed — no namespace dot.
		"method",
		"http",
		// Unknown http.* field — would be a Scheme / Manifest mismatch.
		"http.nope",
		"http.uri.path", // historically-proposed dotted name — Catalog forbids it
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			if got, ok := r.Resolve(field, ev); ok {
				t.Errorf("Resolve(%q): want ok=false, got true (value=%s)", field, got)
			}
		})
	}
}

// ========================== 4. IP failure modes =============================================

// TestHttpResolver_IPFailures covers the three conditions under which toIPValue must
// reject: empty string, malformed IP literal, CIDR literal in an ip field. Each one
// is a configuration / data bug; surfacing as (Value{}, false) is the right contract.
func TestHttpResolver_IPFailures(t *testing.T) {
	r := HttpResolver{}

	cases := []struct {
		name     string
		entry    *parser.LogEntry
		wantFail bool
	}{
		{
			name:     "empty_real_ip",
			entry:    &parser.LogEntry{RealIP: ""},
			wantFail: true,
		},
		{
			name:     "empty_remote_addr",
			entry:    &parser.LogEntry{RemoteAddr: ""},
			wantFail: true,
		},
		{
			name:     "malformed_real_ip",
			entry:    &parser.LogEntry{RealIP: "not.an.ip"},
			wantFail: true,
		},
		{
			name:     "cidr_in_real_ip",
			entry:    &parser.LogEntry{RealIP: "10.0.0.0/8"},
			wantFail: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := makeEvent(tc.entry)
			// RealIP
			if _, ok := r.Resolve("http.real_ip", ev); ok == tc.wantFail {
				t.Errorf("http.real_ip ok=%v, want=%v", !tc.wantFail, tc.wantFail)
			}
			// RemoteAddr — same path through toIPValue
			if _, ok := r.Resolve("http.remote_addr", ev); ok == tc.wantFail {
				t.Errorf("http.remote_addr ok=%v, want=%v", !tc.wantFail, tc.wantFail)
			}
		})
	}
}

// ========================== 5. *threat.ThreatEvent =========================================

// TestHttpResolver_ThreatEvent asserts that the collapse path (LogEntry → ThreatEvent)
// still answers http.real_ip — the only HTTP field that survives the scoring step —
// and rejects every other http.* field, because ThreatEvent has no other HTTP data.
func TestHttpResolver_ThreatEvent(t *testing.T) {
	te := &threat.ThreatEvent{IP: "203.0.113.42"}
	ev := makeEvent(te)
	r := HttpResolver{}

	// real_ip succeeds — ThreatEvent.IP → NewIP.
	t.Run("real_ip_ok", func(t *testing.T) {
		got, ok := r.Resolve("http.real_ip", ev)
		if !ok {
			t.Fatalf("Resolve(http.real_ip): want ok=true, got false")
		}
		ip, ok := got.AsIP()
		if !ok {
			t.Fatalf("Resolve(http.real_ip): kind=%s, want IP", got.Kind())
		}
		if !ip.Equal(net.ParseIP("203.0.113.42")) {
			t.Errorf("Resolve(http.real_ip): want 203.0.113.42, got %s", ip)
		}
	})

	// All other http.* fields must surface as (Value{}, false) — there is no
	// method, path, status etc. on ThreatEvent.
	otherFields := []string{
		"http.method", "http.path", "http.query", "http.raw_uri",
		"http.status", "http.bytes_sent", "http.referer", "http.user_agent",
		"http.remote_addr", "http.protocol", "http.remote_user",
	}
	for _, field := range otherFields {
		t.Run(field+"_false", func(t *testing.T) {
			if _, ok := r.Resolve(field, ev); ok {
				t.Errorf("Resolve(%q): want ok=false (ThreatEvent has no such field)", field)
			}
		})
	}
}

// TestHttpResolver_ThreatEvent_InvalidIP covers the empty-IP edge case for the
// ThreatEvent path too — toIPValue is shared, so the same rules apply.
func TestHttpResolver_ThreatEvent_InvalidIP(t *testing.T) {
	te := &threat.ThreatEvent{IP: ""}
	ev := makeEvent(te)
	r := HttpResolver{}
	if _, ok := r.Resolve("http.real_ip", ev); ok {
		t.Errorf("Resolve(http.real_ip) with empty ThreatEvent.IP: want ok=false, got true")
	}
}

// ========================== 6. Other payload shapes =========================================

// TestHttpResolver_OtherPayloads asserts the resolver treats every Payload shape it
// does not know about as opaque (Value{}, false). The branch is the default of the
// type switch — this test just pins the contract so a future refactor cannot
// accidentally accept string / int payloads.
func TestHttpResolver_OtherPayloads(t *testing.T) {
	r := HttpResolver{}

	cases := []struct {
		name    string
		payload any
	}{
		{"nil_payload", nil},
		{"string_payload", "hello"},
		{"int_payload", 42},
		{"event_with_no_payload", &plugin.Event{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &plugin.Event{Payload: tc.payload}
			if _, ok := r.Resolve("http.method", ev); ok {
				t.Errorf("Resolve(http.method, payload=%T): want ok=false, got true", tc.payload)
			}
		})
	}
}
