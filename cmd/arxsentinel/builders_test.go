// ========================== cmd/arxsentinel — builders_test.go =========================
//   Unit tests for the product-side bridge between sink config and concrete
//   format.Formatter (buildSinks / formatterForFormat).
//
//   Why a separate file: builders.go mixes a lot of orchestration concerns
//   (detector wiring, source wiring, sink wiring). The formatter-bridge
//   logic is the only piece with non-trivial decision branches that need
//   regression coverage — every other builder path is exercised through the
//   end-to-end integration suite, where a unit test here saves a full
//   docker spin-up per fix.
//
//   Regression target (Flow 083, Task 2.2 follow-up, 2bcb354): the
//   `formatterForFormat` switch was driven by the YAML `format` field
//   alone, with `""` falling back to `FailbanFormatter`. A
//   `sentinel-threat` sink declares no `format` field in the YAML (its
//   wire format is implicit), so it ended up wired with a FailbanFormatter
//   and the NCS queue received Fail2Ban lines that the executor's JSON
//   decoder could not parse. The `sinkType == "sentinel-threat"` branch
//   added in the fix is what locks the correct Formatter in regardless
//   of the (absent) `format` hint.
//
//   Gate B (Flow 083 / Task 3.3): the Formatter impls (Failban / JSON /
//   Sentinel) now live in internal/threat/format — the
//   test imports threatformat for the concrete type assertions and
//   sinkformat for the core interface type.

package main

import (
	"reflect"
	"strings"
	"testing"

	sinkformat "github.com/mr-addams/arx-core/pkg/sink/format"

	threatformat "github.com/mr-addams/arxsentinel/internal/threat/format"
)

// TestFormatterForFormat_SentinelThreatIgnoresFormatHint is the regression
// test for the Phase 2.2 follow-up (Flow 083, 2bcb354). The sink type
// decides the wire format for sentinel-threat — the YAML `format` field
// is irrelevant because the consumer side (queueEventSource.Pop) hard-codes
// `json.Unmarshal(data, &plugin.ThreatEvent{})` and the producer side
// (FormatSentinelThreat) produces that exact byte layout.
func TestFormatterForFormat_SentinelThreatIgnoresFormatHint(t *testing.T) {
	// Empty format (the normal case — cf-executor.yaml / ros-executor.yaml /
	// nginx-executor.yaml do not declare `format` on the sentinel-threat output).
	f, err := formatterForFormat("sentinel-threat", "", "cf-test")
	if err != nil {
		t.Fatalf("formatterForFormat(sentinel-threat, \"\"): %v", err)
	}
	if _, ok := f.(*threatformat.SentinelFormatter); !ok {
		t.Errorf("sentinel-threat sink with empty format: got %T, want *SentinelFormatter", f)
	}

	// Even an explicit "fail2ban" format hint must not change the wire format
	// for a sentinel-threat sink — the consumer side decodes JSON, so the
	// producer must emit JSON regardless of the user's preference.
	f, err = formatterForFormat("sentinel-threat", "fail2ban", "cf-test")
	if err != nil {
		t.Fatalf("formatterForFormat(sentinel-threat, fail2ban): %v", err)
	}
	if _, ok := f.(*threatformat.SentinelFormatter); !ok {
		t.Errorf("sentinel-threat sink with fail2ban hint: got %T, want *SentinelFormatter", f)
	}
}

// TestFormatterForFormat_FileAndStdoutUseFormatHint covers the file/stdout
// paths — the `format` field is the only thing the user controls, and it
// must drive the Formatter choice (no sink-type override for these).
func TestFormatterForFormat_FileAndStdoutUseFormatHint(t *testing.T) {
	cases := []struct {
		sinkType, format string
		want             string
	}{
		{"file", "", "*FailbanFormatter"},
		{"file", "fail2ban", "*FailbanFormatter"},
		{"file", "json", "*JSONFormatter"},
		{"stdout", "", "*FailbanFormatter"},
		{"stdout", "json", "*JSONFormatter"},
	}
	for _, tc := range cases {
		t.Run(tc.sinkType+"/"+tc.format, func(t *testing.T) {
			f, err := formatterForFormat(tc.sinkType, tc.format, "stream")
			if err != nil {
				t.Fatalf("formatterForFormat(%q, %q): %v", tc.sinkType, tc.format, err)
			}
			got := typeName(f)
			if !strings.HasSuffix(got, tc.want) {
				t.Errorf("got %s, want suffix %s", got, tc.want)
			}
		})
	}
}

// TestFormatterForFormat_UnknownFormatRejected guards the "fail fast on
// misconfiguration" contract — file/stdout sinks reject unknown format
// strings so a typo in the YAML surfaces at startup instead of silently
// emitting empty threat logs.
func TestFormatterForFormat_UnknownFormatRejected(t *testing.T) {
	_, err := formatterForFormat("file", "xml", "stream")
	if err == nil {
		t.Fatal("formatterForFormat(file, xml): want error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error must mention unknown format, got: %v", err)
	}
}

// typeName returns the dynamic type name of f without the package path
// prefix — keeps the assertion output stable across toolchain changes.
func typeName(f sinkformat.Formatter) string {
	if f == nil {
		return "<nil>"
	}
	// All Formatter impls are *T — reflect.Type.String() returns "*pkg.T".
	// We only need the tail after the last "." to keep the table readable.
	full := reflect.TypeOf(f).String()
	if idx := strings.LastIndex(full, "."); idx >= 0 {
		full = full[idx+1:]
	}
	return "*" + full
}
