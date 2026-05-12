//go:build e2e

// ========================== E2E тест — Task 5.4 =======================================
//   Прогоняет .reference/example.access.log через реальный pipeline без TailReader
//   и без whitelist/DNS. Проверяет что известные вредоносные IP попадают в threat-лог
//   и что формат строк совместим с Fail2Ban.
//
//   Запуск: go test -run TestE2E -tags e2e -v .
//
//   НЕ включён в регулярный go test ./...:
//     whitelist/DNS не нужен — тест проверяет только детекторы;
//     build tag e2e изолирует от CI.

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/output"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/core/scorer"
	"github.com/mr-addams/nginx-sentinel/internal/core/state"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// fail2banRE — regexp полной структуры строки threat-лога.
// Воспроизводит failregex из deploy/fail2ban/filter.d/nginx-sentinel.conf
// и дополнительно проверяет наличие modules= и reason= — регрессия формата видна сразу.
// modules=\S* (не \S+): поле может быть пустым при carry-over score без новых детекторов.
var fail2banRE = regexp.MustCompile(`(WARN|THREAT)\s+\S+\s+score=\d+\s+modules=\S*\s+reason=`)

func TestE2E(t *testing.T) {
	// ── Config: Go-дефолты, без файла конфига ─────────────────────────────────────────
	// LoadConfig("") → os.ReadFile("") → ENOENT → возвращает defaultConfig() без ошибки.
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// ── Pipeline: tracker + scorer с 7 детекторами ───────────────────────────────────
	// logFn — no-op, чтобы не засорять вывод теста детальными логами детекторов.
	nopLog := func(_, _, _ string) {}

	tracker := state.NewTracker(cfg, nopLog)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), nopLog)

	// ── ThreatLogger: захватывает вывод в срез ────────────────────────────────────────
	// В продакшне writeFn = utils.LogThreat (пишет в файл + консоль).
	// Здесь — захват в память для проверки формата и содержимого.
	var threatLines []string
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		line := output.FormatThreatLine(ip, score, level, modules, reason)
		threatLines = append(threatLines, line)
	})

	// ── Прогон example.access.log ─────────────────────────────────────────────────────
	logPath := ".reference/example.access.log"
	f, err := os.Open(logPath)
	if err != nil {
		// Файл не в git — локальный артефакт. Пропускаем тест а не падаем,
		// чтобы отличить отсутствие тестовых данных от логической ошибки.
		t.Skipf("файл %s недоступен, пропуск e2e: %v", logPath, err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		entry, ok := parser.Parse(scan.Text())
		if !ok {
			continue
		}
		ipState := tracker.Update(entry)
		level, score, modules, reason := sc.Evaluate(ipState, entry)
		threatLogger.Log(entry.RealIP, score, level, modules, reason)
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("ошибка чтения %s: %v", logPath, err)
	}

	t.Logf("e2e: обработан %s, threat/warn записей: %d", logPath, len(threatLines))

	// ── Утверждение 1: есть хотя бы один THREAT ──────────────────────────────────────
	// 185.177.72.23 (162 запроса за 97 сек) → rate + UA(curl) → score > ban_threshold=80.
	threatCount := countLevel(threatLines, " THREAT ")
	if threatCount == 0 {
		t.Errorf("ожидали >= 1 THREAT-записи, получили 0 (всего записей: %d)", len(threatLines))
		for _, line := range threatLines {
			t.Logf("  %s", line)
		}
	}

	// ── Утверждение 2: все строки матчатся Fail2Ban regex ─────────────────────────────
	// Критично: если формат не совпадает, Fail2Ban не заблокирует атакующих.
	for _, line := range threatLines {
		if !fail2banRE.MatchString(line) {
			t.Errorf("строка не матчит Fail2Ban regex %q: %s", fail2banRE, line)
		}
	}

	// ── Утверждение 3: 185.177.72.23 попал под THREAT ────────────────────────────────
	// IP известен по примеру из документации: 162 запроса за 97s с curl/8.7.1.
	const knownBadIP = "185.177.72.23"
	if !hasIPAtLevel(threatLines, knownBadIP, " THREAT ") {
		t.Errorf("ожидали THREAT для %s (rate+UA детекторы), не нашли", knownBadIP)
		found := filterByIP(threatLines, knownBadIP)
		if len(found) == 0 {
			t.Logf("  %s вообще не попал в threat-лог", knownBadIP)
		} else {
			for _, line := range found {
				t.Logf("  %s", line)
			}
		}
	}

	t.Logf("e2e: THREAT=%d, WARN=%d",
		threatCount,
		countLevel(threatLines, " WARN "),
	)
}

// ========================== Вспомогательные функции ===================================

func countLevel(lines []string, level string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, level) {
			n++
		}
	}
	return n
}

func hasIPAtLevel(lines []string, ip, level string) bool {
	target := fmt.Sprintf("%s %s score=", level[1:len(level)-1], ip) // "THREAT 1.2.3.4 score="
	for _, line := range lines {
		if strings.Contains(line, target) {
			return true
		}
	}
	return false
}

func filterByIP(lines []string, ip string) []string {
	var result []string
	for _, line := range lines {
		if strings.Contains(line, " "+ip+" ") {
			result = append(result, line)
		}
	}
	return result
}
