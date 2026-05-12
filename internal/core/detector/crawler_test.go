// ========================== Тесты CrawlerDetector =====================================
//   Табличные тесты: числовая последовательность срабатывает, случайные числа нет,
//   дубликаты в последовательности, enabled=false, мало путей.
//
//   Тесты hasConsecutiveSequence и parseNumericPath — отдельные unit-тесты.
//
//   mockIPView определён в rate_test.go — общий для всех тестов пакета.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
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
		// ── Числовая последовательность ───────────────────────────────────────────────────
		{
			name: "5 последовательных /page/N → срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		{
			name: "7 последовательных → срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/items/10", "/items/11", "/items/12",
				"/items/13", "/items/14", "/items/15", "/items/16",
			},
			wantScore: true,
		},
		{
			name: "последовательность начинается не с 1 → срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/products/42", "/products/43", "/products/44", "/products/45", "/products/46",
			},
			wantScore: true,
		},
		{
			name: "последовательность в смеси с другими путями → срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/about", "/page/1", "/index.html", "/page/2",
				"/logo.png", "/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		{
			name: "последовательность с дубликатами → срабатывает (дубли не ломают счёт)",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/2", // дубль
				"/page/3", "/page/4", "/page/5",
			},
			wantScore: true,
		},
		// ── Не последовательность ────────────────────────────────────────────────────────
		{
			name: "только 4 последовательных (< min=5) → не срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/page/1", "/page/2", "/page/3", "/page/4",
			},
			wantScore: false,
		},
		{
			name: "случайные числа без последовательности → не срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/post/100", "/post/5", "/post/42", "/post/200", "/post/7",
			},
			wantScore: false,
		},
		{
			name: "пути без цифр → не срабатывает",
			cfg:  baseCfg,
			recentPaths: []string{
				"/about", "/contact", "/index.html", "/products", "/faq",
			},
			wantScore: false,
		},
		{
			name:        "меньше min_sequential путей → не срабатывает",
			cfg:         baseCfg,
			recentPaths: []string{"/page/1", "/page/2", "/page/3"},
			wantScore:   false,
		},
		{
			name:        "пустой список путей → не срабатывает",
			cfg:         baseCfg,
			recentPaths: []string{},
			wantScore:   false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: последовательность не срабатывает при enabled=false",
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
				t.Errorf("ожидали Score > 0, получили 0 (paths=%v)", tt.recentPaths)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (paths=%v)", result.Score, tt.recentPaths)
			}
			if result.Score > 0 {
				if result.Module != "crawler" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "crawler")
				}
				if result.Reason == "" {
					t.Error("Reason пустой при Score > 0")
				}
			}
		})
	}
}

// ========================== Тесты parseNumericPath ====================================

func TestParseNumericPath(t *testing.T) {
	tests := []struct {
		path       string
		wantPrefix string
		wantNum    int
		wantOk     bool
	}{
		{"/page/5", "/page/", 5, true},
		{"/items/42", "/items/", 42, true},
		{"/page/1/", "/page/", 1, true}, // trailing slash поглощается regex /?$
		{"/5", "/", 5, true},
		{"/archive/2024", "/archive/", 2024, true},
		{"/about", "", 0, false},      // нет цифр
		{"/index.html", "", 0, false}, // суффикс не цифровой (html)
		{"", "", 0, false},
		{"/api/v2", "", 0, false},  // slug-число — не отдельный сегмент (/v2 ≠ /N)
		{"/item5", "", 0, false},   // число — суффикс slug, не отдельный сегмент
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			prefix, num, ok := parseNumericPath(tt.path)
			if ok != tt.wantOk {
				t.Errorf("ok=%v, ожидали %v", ok, tt.wantOk)
			}
			if ok {
				if prefix != tt.wantPrefix {
					t.Errorf("prefix=%q, ожидали %q", prefix, tt.wantPrefix)
				}
				if num != tt.wantNum {
					t.Errorf("num=%d, ожидали %d", num, tt.wantNum)
				}
			}
		})
	}
}

// ========================== Тесты hasConsecutiveSequence ==============================

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
		{"1,3,5,7,9 → false (нет соседних)", []int{1, 3, 5, 7, 9}, 3, false},
		{"1,2,2,3,4,5 → true (с дублями)", []int{1, 2, 2, 3, 4, 5}, 5, true},
		{"пустой срез → false", []int{}, 3, false},
		{"один элемент, min=1 → true", []int{42}, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasConsecutiveSequence(tt.nums, tt.minLen)
			if got != tt.want {
				t.Errorf("hasConsecutiveSequence(%v, %d) = %v, ожидали %v",
					tt.nums, tt.minLen, got, tt.want)
			}
		})
	}
}
