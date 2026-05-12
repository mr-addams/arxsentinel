// ========================== Модуль output/logger ========================================
//   Запись WARN/THREAT событий в threat-лог в формате для Fail2Ban.
//
//   ЧТО ЗДЕСЬ:
//     - ThreatLogger — принимает вердикт scorer и записывает строку в лог
//     - Log() — единственная публичная функция; не пишет при level = "" (норма)
//
//   ФОРМАТ СТРОКИ (читается Fail2Ban filter'ом, Task 5.1):
//     2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="..."
//
//   ИЗОЛЯЦИЯ:
//     ThreatLogger не импортирует sys/utils напрямую — writeFn инжектируется
//     из main.go. В тестах writeFn захватывает вывод в strings.Builder.
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Консольное логирование (sys/utils.Log) — вызов через logFn в writeFn
//     - Агрегация score (scorer/)
//     - Открытие файлов (sys/utils.Init)

package output

import (
	"fmt"
	"strings"
	"time"
)

// ========================== ThreatLogger ==============================================

// ThreatLogger записывает события угроз в threat-лог.
//
// writeFn в продакшне = utils.LogThreat (записывает в threats.log + дублирует в консоль).
// writeFn в тестах = функция, захватывающая вывод в буфер для проверки формата.
type ThreatLogger struct {
	writeFn func(ip string, score int, level string, modules []string, reason string)
}

// NewThreatLogger создаёт ThreatLogger с инжектированной функцией записи.
// writeFn должна обеспечивать запись строки в threat-лог и консоль.
func NewThreatLogger(writeFn func(ip string, score int, level string, modules []string, reason string)) *ThreatLogger {
	return &ThreatLogger{writeFn: writeFn}
}

// Log записывает событие угрозы если level не пустой (WARN или THREAT).
//
// При level = "" (нормальная активность) — молча возвращает, ничего не пишет.
// Это главный фильтр: scorer вызывает Evaluate для каждой строки, но в лог
// попадают только аномальные события — иначе threats.log переполнился бы.
//
// Вызывается из main pipeline после scorer.Evaluate.
func (l *ThreatLogger) Log(ip string, score int, level string, modules []string, reason string) {
	if level == "" {
		return
	}
	l.writeFn(ip, score, level, modules, reason)
}

// ========================== Форматирование строки =====================================

// FormatThreatLine форматирует одну строку threat-лога.
//
// Публичная функция — используется в тестах для проверки формата строки.
// utils.LogThreat форматирует строку независимо (sys/ не импортирует core/).
// Формат совместим с Fail2Ban: timestamp level ip score=N modules=... reason="..."
//
// Пример:
//
//	2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="probe:env:3,rate:142rps"
func FormatThreatLine(ip string, score int, level string, modules []string, reason string) string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	modulesStr := strings.Join(modules, ",")
	return fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, level, ip, score, modulesStr, reason)
}
