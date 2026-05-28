// ========================== CrawlerDetector tests =====================================
//   Table-driven tests: numeric sequence triggers, random numbers do not,
//   duplicates in sequence, enabled=false, too few paths.
//
//   Tests for hasConsecutiveSequence and parseNumericPath — separate unit tests.
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

func TestCrawlerDetector(t *testing.T) {
	baseCfg := config.CrawlerConfig{
		Enabled:       true,
		MinSequential: 5,
		Score:         20,
	}

	tests := []struct {
		name        string
		cfg         config.CrawlerConfig
		recentPaths []string
		wantScore   bool
	}{
		// ── Numeric sequence ──────────────────────────────────────────────────────────────
		{
			name: "5 consecutive /page/N → triggers",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		{
			name: "7 consecutive → triggers",
			cfg:  baseCfg,
			recentPaths: []string{
				"/items/10", "/items/11", "/items/12",
				"/items/13", "/items/14", "/items/15", "/items/16",
			},
			wantScore: true,
		},
		{
			name: "sequence not starting from 1 → triggers",
			cfg:  baseCfg,
			recentPaths: []string{
				"/products/42", "/products/43", "/products/44", "/products/45", "/products/46",
			},
			wantScore: true,
		},
		{
			name: "sequence mixed with other paths → triggers",
			cfg:  baseCfg,
			recentPaths: []string{
				"/about", "/page/1", "/index.html", "/page/2",
				"/logo.png", "/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		{
			name: "sequence with duplicates → triggers (duplicates do not break the count)",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/2", // duplicate
				"/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		// ── Not a sequence ────────────────────────────────────────────────────────────────
		{
			name: "only 4 consecutive (< min=5) → no trigger",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/3", "/page/4",
			},
			wantScore: false,
		},
		{
			name: "random numbers without sequence → no trigger",
			cfg:  baseCfg,
			recentPaths: []string{
				"/post/100", "/post/5", "/post/42", "/post/200", "/post/7",
			},
			wantScore: false,
		},
		{
			name: "paths without digits → no trigger",
			cfg:  baseCfg,
			recentPaths: []string{
				"/about", "/contact", "/index.html", "/products", "/faq",
			},
			wantScore: false,
		},
		{
			name:        "fewer than min_sequential paths → no trigger",
			cfg:         baseCfg,
			recentPaths: []string{"/page/1", "/page/2", "/page/3"},
			wantScore:   false,
		},
		{
			name:        "empty path list → no trigger",
			cfg:         baseCfg,
			recentPaths: []string{},
			wantScore:   false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: sequence does not trigger when enabled=false",
			cfg: config.CrawlerConfig{
				Enabled:       false,
				MinSequential: 5,
				Score:         20,
			},
			recentPaths: []string{
				"/page/1", "/page/2", "/page/3", "/page/4", "/page/5",
			},
			wantScore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewCrawlerDetector(tt.cfg)
			mv := &mockIPView{recentPaths: tt.recentPaths}
			result := d.Detect(mv, &parser.LogEntry{})

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (paths=%v)", tt.recentPaths)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (paths=%v)", result.Score, tt.recentPaths)
			}
			if result.Score > 0 {
				if result.Module != "crawler" {
					t.Errorf("Module = %q, expected %q", result.Module, "crawler")
				}
				if result.Reason == "" {
					t.Error("Reason is empty when Score > 0")
				}
			}
		})
	}
}

// ========================== parseNumericPath tests ====================================

func TestParseNumericPath(t *testing.T) {
	tests := []struct {
		path       string
		wantPrefix string
		wantNum    int
		wantOk     bool
	}{
		{"/page/5", "/page/", 5, true},
		{"/items/42", "/items/", 42, true},
		{"/page/1/", "/page/", 1, true}, // trailing slash absorbed by regex /?$
		{"/5", "/", 5, true},
		{"/archive/2024", "/archive/", 2024, true},
		{"/about", "", 0, false},      // no digits
		{"/index.html", "", 0, false}, // suffix is not numeric (html)
		{"", "", 0, false},
		{"/api/v2", "", 0, false},  // slug-number — not a standalone segment (/v2 ≠ /N)
		{"/item5", "", 0, false},   // number is a slug suffix, not a standalone segment
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			prefix, num, ok := parseNumericPath(tt.path)
			if ok != tt.wantOk {
				t.Errorf("ok=%v, expected %v", ok, tt.wantOk)
			}
			if ok {
				if prefix != tt.wantPrefix {
					t.Errorf("prefix=%q, expected %q", prefix, tt.wantPrefix)
				}
				if num != tt.wantNum {
					t.Errorf("num=%d, expected %d", num, tt.wantNum)
				}
			}
		})
	}
}

// ========================== hasConsecutiveSequence tests ==============================

func TestHasConsecutiveSequence(t *testing.T) {
	tests := []struct {
		name   string
		nums   []int
		minLen int
		want   bool
	}{
		{"1,2,3,4,5 → true (min=5)", []int{1, 2, 3, 4, 5}, 5, true},
		{"1,2,3,4 → false (min=5)", []int{1, 2, 3, 4}, 5, false},
		{"5,1,2,3,4,6 → true (min=5, unsorted)", []int{5, 1, 2, 3, 4, 6}, 5, true},
		{"1,3,5,7,9 → false (no adjacent)", []int{1, 3, 5, 7, 9}, 3, false},
		{"1,2,2,3,4,5 → true (with duplicates)", []int{1, 2, 2, 3, 4, 5}, 5, true},
		{"empty slice → false", []int{}, 3, false},
		{"single element, min=1 → true", []int{42}, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasConsecutiveSequence(tt.nums, tt.minLen)
			if got != tt.want {
				t.Errorf("hasConsecutiveSequence(%v, %d) = %v, expected %v",
					tt.nums, tt.minLen, got, tt.want)
			}
		})
	}
}
