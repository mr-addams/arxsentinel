// ========================== UserAgent detector tests =====================================
//   Tests for UA detector: built-in patterns, extra pattern normalization,
//   case-insensitive matching via pre-normalization.

package useragent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	_ "github.com/mr-addams/arxsentinel/pkg/detector/useragent"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// TestUADetector_ExtraPatternNormalization verifies that extra patterns with
// mixed case are normalized to lowercase during factory creation and correctly
// detected via Detect(). Also verifies normalization is irreversible: the
// Reason field contains the lowercased pattern, never the original case.
func TestUADetector_ExtraPatternNormalization(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"extra_scanner_patterns":    []interface{}{"MyBot", "CustomScanner"},
			"extra_grabber_patterns":    []interface{}{"MyGrabber"},
			"extra_automation_patterns": []interface{}{"GoClient"},
		},
	}
	d, err := detector.Build(context.Background(), "ua", cfg, nil)
	if err != nil {
		t.Fatalf("Build(ua, extra) error: %v", err)
	}

	sv := newStubView(0, 0, nil, 0)

	// ── Mixed-case extra patterns are detected after normalization ───────────────
	t.Run("mixed_case_extra_detected", func(t *testing.T) {
		cases := []struct {
			ua   string // original case User-Agent (will be lowered by Detect)
			want string // expected substring in Reason (must be lowercase)
		}{
			{"MyBot/2.0", "mybot"},
			{"MyGrabber/1.0", "mygrabber"},
			{"GoClient/1.0", "goclient"},
			{"CustomScanner/1.0", "customscanner"},
			{"MYBOT/2.0", "mybot"},         // all-upper UA is also lowered before matching
			{"MYGRABBER/2.0", "mygrabber"}, // all-upper grabber → lowered → matches
		}
		for _, tc := range cases {
			result := d.Detect(sv, &plugin.LogEntry{UserAgent: tc.ua})
			if result.Score == 0 {
				t.Errorf("Detect(%q) should score, got 0", tc.ua)
			}
			if !strings.Contains(result.Reason, tc.want) {
				t.Errorf("Detect(%q) Reason = %q, want containing %q",
					tc.ua, result.Reason, tc.want)
			}
		}
	})

	// ── Normalization is irreversible: Reason uses the lowercased form ──────────
	t.Run("reason_uses_normalized_lowercase", func(t *testing.T) {
		// If "MyBot" were stored as-is (not normalized), Reason would contain
		// "MyBot". Since normalization happens in the factory, Reason contains
		// the lowercased "mybot".
		result := d.Detect(sv, &plugin.LogEntry{UserAgent: "MyBot/2.0"})
		if strings.Contains(result.Reason, "MyBot") {
			t.Errorf("Reason should NOT contain original-case 'MyBot', got %q",
				result.Reason)
		}
		if !strings.Contains(result.Reason, "mybot") {
			t.Errorf("Reason should contain lowercased 'mybot', got %q",
				result.Reason)
		}
	})
}

// TestUADetector_ExtraPatternNoMatchAfterNormalization verifies that the
// original mixed-case form of an extra pattern is no longer stored after
// normalization. This is the companion to the irreversibility test: if a
// client sends a UA that ONLY matches the original-case pattern name
// (but NOT the lowercased version), it will not match — proving the pattern
// was permanently normalized at factory time.
//
// Practically, this means: pattern "MyBot" becomes "mybot". UA "MyBot" becomes
// "mybot" via ToLower, so it matches. But the stored pattern "MyBot" is gone
// forever — only "mybot" exists.
func TestUADetector_ExtraPatternNoMatchAfterNormalization(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"extra_automation_patterns": []interface{}{"RareBot"},
		},
	}
	d, err := detector.Build(context.Background(), "ua", cfg, nil)
	if err != nil {
		t.Fatalf("Build(ua, extra) error: %v", err)
	}

	sv := newStubView(0, 0, nil, 0)

	// "RareBot" in the UA triggers detection because both are lowered.
	result := d.Detect(sv, &plugin.LogEntry{UserAgent: "RareBot/1.0"})
	if result.Score == 0 {
		t.Error("Detect('RareBot/1.0') should score — input is lowered to 'rarebot/1.0' and matches 'rarebot'")
	}

	// The Reason MUST contain the lowercased "rarebot", never "RareBot".
	if strings.Contains(result.Reason, "RareBot") {
		t.Errorf("Reason must NOT contain original-case 'RareBot', got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, "rarebot") {
		t.Errorf("Reason must contain lowercased 'rarebot', got %q", result.Reason)
	}
}

// TestUADetector_BuiltinPatterns verifies built-in patterns work
// regardless of input UA case — both lowercase and uppercase variants
// are detected through the pre-normalized pattern list.
func TestUADetector_BuiltinPatterns(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "ua", cfg, nil)
	if err != nil {
		t.Fatalf("Build(ua) error: %v", err)
	}

	sv := newStubView(0, 0, nil, 0)

	cases := []struct {
		ua   string
		want bool
	}{
		{"nuclei/3.0", true},
		{"NUCLEI/3.0", true}, // all-upper UA → lowered → matches
		{"Nuclei/3.0", true}, // mixed-case UA → lowered → matches
		{"Mozilla/5.0", false},
	}
	for _, tc := range cases {
		result := d.Detect(sv, &plugin.LogEntry{UserAgent: tc.ua})
		if tc.want && result.Score == 0 {
			t.Errorf("Detect(%q) should score, got 0", tc.ua)
		}
		if !tc.want && result.Score != 0 {
			t.Errorf("Detect(%q) should not score, got %d", tc.ua, result.Score)
		}
	}
}

// stubView implements plugin.IPView for test use.
type stubView struct {
	total    int
	count404 int
	paths    []string
	rate     float64
}

func newStubView(total, count404 int, paths []string, rate float64) plugin.IPView {
	return &stubView{total: total, count404: count404, paths: paths, rate: rate}
}

func (s *stubView) GetIP() string                      { return "1.2.3.4" }
func (s *stubView) GetTotalRequests() int              { return s.total }
func (s *stubView) GetRequests404() int                { return s.count404 }
func (s *stubView) RecentPaths() []string              { return s.paths }
func (s *stubView) ApproxRate(_ time.Duration) float64 { return s.rate }
