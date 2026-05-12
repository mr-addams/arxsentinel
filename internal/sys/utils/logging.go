// ========================== Модуль utils/logging ========================================
//   Три потока логирования: console (цветной stdout), operational (sentinel.log),
//   threat (threats.log). Тегированный вывод по принципам logging.go из telegram-бота.
//
//   ЧТО ЗДЕСЬ:
//     - Init() — инициализация файловых логгеров
//     - Log(tag, msg, level) — консоль + sentinel.log
//     - LogThreat() — запись в threats.log (формат для Fail2Ban)
//     - Close() — закрытие файловых дескрипторов
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Конфигурационные структуры (sys/config)
//
//   ТЕГИ (outer): STARTUP, SHUTDOWN, CONFIG, PARSER, DETECTOR, SCORER,
//                 WHITELIST, THREAT, STATS, GC, TAIL, ERROR, WARN, INFO, DEBUG
//   ВНУТРЕННИЕ ТЕГИ (inner): PROBE, RATE, UA, BRUTEFORCE, CRAWLER, NOASSET,
//                            OVERFLOW, DNS, GC
//
//   ФИЛЬТРАЦИЯ:
//     debugOnlyTags — видны только при DebugEnabled=true
//     quietTags     — показывают только error/warning без debug-режима

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// ========================== Глобальное состояние =======================================
//
// logMu защищает operationalWriter и threatWriter от concurrent access при SIGHUP reload:
// GC-горутина вызывает Log/LogThreat параллельно с Reload() в main-горутине.
// Читатели (Log, LogThreat) берут RLock; Reload берёт Lock для swap дескрипторов.

var (
	// debugEnabled / colorEnabled — атомики: читаются из Log без лока (fast path),
	// обновляются в Init/Reload из main-горутины.
	debugEnabled atomic.Bool
	colorEnabled atomic.Bool

	// logMu защищает operationalWriter и threatWriter.
	logMu sync.RWMutex

	// operationalWriter — файловый дескриптор для sentinel.log.
	// nil если файл не удалось открыть — продолжаем с консолью только.
	operationalWriter *os.File

	// threatWriter — файловый дескриптор для threats.log.
	// nil если файл не удалось открыть — Init вернёт ошибку.
	threatWriter *os.File
)

func init() {
	colorEnabled.Store(true) // цвета включены по умолчанию до явного Init
}

// ========================== Инициализация цветов =======================================

// Цветовые переменные — приватные, используются только внутри пакета.
// core/ не импортирует sys/utils напрямую, поэтому экспорт не нужен.
var (
	timestampColor = color.New(color.FgBlue)
	blueColor      = color.New(color.FgBlue)
	redColor       = color.New(color.FgRed)
	yellowColor    = color.New(color.FgYellow)
	magentaColor   = color.New(color.FgMagenta)
	cyanColor      = color.New(color.FgCyan)
	greenColor     = color.New(color.FgGreen)
	orangeColor    = color.New(color.FgHiRed)
)

// logColors — цвета для outer-тегов.
// Семантика: зелёный = успех/старт, красный = угроза/ошибка, жёлтый = предупреждение,
// голубой = информационный, пурпурный = конфигурация.
var logColors = map[string]*color.Color{
	"STARTUP":   greenColor,
	"SHUTDOWN":  redColor,
	"CONFIG":    magentaColor,
	"PARSER":    cyanColor,
	"DETECTOR":  yellowColor,
	"SCORER":    cyanColor,
	"WHITELIST": magentaColor,
	"THREAT":    redColor,
	"STATS":     greenColor,
	"GC":        cyanColor,
	"TAIL":      cyanColor,
	"ERROR":     redColor,
	"WARN":      yellowColor,
	"INFO":      cyanColor,
	"DEBUG":     orangeColor,
}

// innerTagColors — цвета для inner-тегов вида [PROBE] внутри тела сообщения.
var innerTagColors = map[string]*color.Color{
	"PROBE":      yellowColor,
	"RATE":       orangeColor,
	"UA":         magentaColor,
	"BRUTEFORCE": orangeColor,
	"CRAWLER":    yellowColor,
	"NOASSET":    cyanColor,
	"OVERFLOW":   redColor,
	"DNS":        blueColor,
	"GC":         cyanColor,
}

// debugOnlyTags — теги видимые только при DebugEnabled=true.
// PARSER и TAIL подавляются в продакшне — они дают строку на каждую запись лога nginx.
var debugOnlyTags = map[string]bool{
	"DEBUG":  true,
	"PARSER": true, // строка на каждую nginx-запись — слишком много в продакшне
	"TAIL":   true, // события inotify файловой системы — debug-шум
}

// quietTags — теги, показывающие только error/warning без debug-режима.
// Detectors и Scorer выдают много сообщений в процессе обработки — нужны
// только при отладке, не в обычном мониторинге.
var quietTags = map[string]bool{
	"DETECTOR": true,
	"SCORER":   true,
}

// ========================== Инициализация =============================================

// Init открывает файловые дескрипторы для operational и threat логов.
// Создаёт директории если не существуют.
//
// Поведение при ошибках:
//   - Operational log недоступен → warning в stderr, продолжаем (консоль работает).
//   - Threat log недоступен → возвращаем ошибку: без него Fail2Ban не работает.
//
// Вызывается из main.go один раз при старте.
func Init(debug, consoleColor bool, operationalLogPath, threatLogPath string) error {
	debugEnabled.Store(debug)
	colorEnabled.Store(consoleColor)

	// Operational log — некритичен, только warn при недоступности
	if err := ensureDir(operationalLogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] не удалось создать директорию для operational log: %v\n", err)
	} else {
		f, err := os.OpenFile(operationalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] operational log недоступен (%s): %v — продолжаем только с консолью\n", operationalLogPath, err)
		} else {
			operationalWriter = f
		}
	}

	// Threat log — критичен: без него Fail2Ban не получает данные
	if err := ensureDir(threatLogPath); err != nil {
		return fmt.Errorf("директория для threat log: %w", err)
	}
	tf, err := os.OpenFile(threatLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("threat log недоступен (%s): %w", threatLogPath, err)
	}
	threatWriter = tf

	return nil
}

// Reload атомарно меняет файловые дескрипторы и флаги после SIGHUP.
// Открывает новые файлы до захвата лока, затем атомарно меняет указатели
// и закрывает старые дескрипторы вне лока (читатели больше не видят old).
//
// Семантика ошибок: operational log некритичен (warn + nil writer);
// threat log критичен — при ошибке возвращает error и не меняет состояние.
func Reload(debug, consoleColor bool, operationalLogPath, threatLogPath string) error {
	// Открываем новые дескрипторы до лока — IO не держит мьютекс
	var newOperWriter *os.File
	if err := ensureDir(operationalLogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Reload: не удалось создать директорию operational log: %v\n", err)
	} else if f, err := os.OpenFile(operationalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		newOperWriter = f
	} else {
		fmt.Fprintf(os.Stderr, "[WARN] Reload: operational log недоступен: %v\n", err)
	}

	if err := ensureDir(threatLogPath); err != nil {
		if newOperWriter != nil {
			newOperWriter.Close()
		}
		return fmt.Errorf("Reload: директория threat log: %w", err)
	}
	newThreatWriter, err := os.OpenFile(threatLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		if newOperWriter != nil {
			newOperWriter.Close()
		}
		return fmt.Errorf("Reload: threat log недоступен (%s): %w", threatLogPath, err)
	}

	// Флаги обновляем только после успешного открытия файлов —
	// при ошибке выше состояние остаётся согласованным (атомики = дескрипторы = старый конфиг).
	debugEnabled.Store(debug)
	colorEnabled.Store(consoleColor)

	// Атомарный swap под write lock — читатели блокируются на минимальное время
	logMu.Lock()
	oldOper, oldThreat := operationalWriter, threatWriter
	operationalWriter = newOperWriter
	threatWriter = newThreatWriter
	logMu.Unlock()

	// Закрываем старые дескрипторы вне лока — читатели уже видят новые
	if oldOper != nil {
		_ = oldOper.Sync()
		_ = oldOper.Close()
	}
	if oldThreat != nil {
		_ = oldThreat.Sync()
		_ = oldThreat.Close()
	}

	return nil
}

// Close сбрасывает буферы ОС и закрывает файловые дескрипторы. Вызывать через defer в main.go.
// Sync() перед Close() гарантирует что последние записи не потеряются при SIGTERM — ядро
// может держать данные в page cache без fsync до явного вызова.
func Close() {
	logMu.Lock()
	ow, tw := operationalWriter, threatWriter
	operationalWriter = nil
	threatWriter = nil
	logMu.Unlock()

	if ow != nil {
		_ = ow.Sync()
		_ = ow.Close()
	}
	if tw != nil {
		_ = tw.Sync()
		_ = tw.Close()
	}
}

// ensureDir создаёт директорию для указанного пути к файлу если не существует.
func ensureDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

// ========================== Основное логирование ======================================

// Log — цветной консольный лог с тегом и timestamp + запись в sentinel.log.
//
// tag: outer-тег (STARTUP, CONFIG, THREAT и т.д.)
// level: "info" | "warning" | "error" | "debug"
//
// Фильтрация:
//   - debugOnlyTags: подавляются в продакшне (DebugEnabled=false)
//   - quietTags: показываются только при error/warning или DebugEnabled=true
//
// Если тело начинается с [TAG] — inner-тег красится отдельным цветом.
func Log(tag, message, level string) {
	// debugOnlyTags: только при явном включении debug-режима
	if debugOnlyTags[tag] && !debugEnabled.Load() {
		return
	}
	// quietTags: в продакшне показываем только важные события
	if quietTags[tag] && !debugEnabled.Load() {
		if level != "error" && level != "warning" {
			return
		}
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// ── Запись в sentinel.log (plain text, без ANSI) ──────────────────────────────────
	// Пишем в файл до форматирования с цветом — избегаем ANSI-кодов в файле.
	// RLock защищает от swap дескриптора при SIGHUP reload.
	logMu.RLock()
	if operationalWriter != nil {
		fmt.Fprintf(operationalWriter, "%s [%s] %s\n", timestamp, tag, message)
	}
	logMu.RUnlock()

	// ── Форматирование для консоли ────────────────────────────────────────────────────

	tagColor, ok := logColors[tag]
	if !ok {
		tagColor = color.New(color.Reset)
	}

	// Извлекаем inner-тег вида [PROBE] из начала тела сообщения.
	// len > 2: минимальная длина [X] = 3 символа — гарантируем что есть что парсить.
	innerName := ""
	innerTagStr := ""
	body := message
	if len(message) > 2 && message[0] == '[' {
		if end := strings.Index(message, "] "); end > 0 {
			name := message[1:end]
			if c, found := innerTagColors[name]; found {
				innerName = name
				innerTagStr = c.Sprintf("[%s]", name) // используется только при ColorEnabled
				body = message[end+2:]
			}
		}
	}

	var line string
	if colorEnabled.Load() {
		ts := timestampColor.Sprint(timestamp)
		t := tagColor.Sprintf("[%s]", tag)
		if innerTagStr != "" {
			line = fmt.Sprintf("%s %s %s %s", ts, t, innerTagStr, body)
		} else {
			line = fmt.Sprintf("%s %s %s", ts, t, body)
		}
	} else {
		// plain text — innerName уже извлечён выше, повторный strings.Index не нужен
		if innerName != "" {
			line = fmt.Sprintf("%s [%s] [%s] %s", timestamp, tag, innerName, body)
		} else {
			line = fmt.Sprintf("%s [%s] %s", timestamp, tag, message)
		}
	}

	fmt.Println(line)
}

// ========================== Threat-лог ================================================

// LogThreat записывает событие угрозы в threats.log (формат для Fail2Ban).
// Дублирует запись в консоль с тегом THREAT.
//
// threatLevel: "WARN" (score 50–79) или "THREAT" (score 80+)
// modules: список сработавших детекторов (["probe", "rate", "useragent"])
// reason: детали по каждому модулю ("env_probe:3,rate:142rps,ua:Nuclei")
//
// Формат строки:
//
//	2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="..."
func LogThreat(ip string, score int, threatLevel string, modules []string, reason string) {
	// RFC3339 — стандарт для машиночитаемых временных меток; совместим с Fail2Ban
	timestamp := time.Now().UTC().Format(time.RFC3339)
	modulesStr := strings.Join(modules, ",")

	line := fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, threatLevel, ip, score, modulesStr, reason)

	// Пишем в threats.log — Fail2Ban читает именно этот файл.
	// RLock защищает от swap дескриптора при SIGHUP reload.
	// nil означает что Init не вызван или был Close() — явно сигнализируем,
	// иначе threat теряется без следа и Fail2Ban слеп к атаке.
	logMu.RLock()
	if threatWriter == nil {
		logMu.RUnlock()
		Log("ERROR", fmt.Sprintf("[THREAT] threatWriter=nil, threat потерян: %s score=%d modules=%s", ip, score, modulesStr), "error")
	} else {
		_, err := fmt.Fprintln(threatWriter, line)
		logMu.RUnlock()
		// Ошибка записи (переполнение диска, инвалидация fd) логируется в stderr напрямую —
		// рекурсия через Log/logMu невозможна, Fail2Ban должен знать о потере записи.
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] threat запись потеряна (%s score=%d): %v\n", ip, score, err)
		}
	}

	// Дублируем в консоль как [THREAT] для мониторинга в реальном времени
	Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q", ip, score, modulesStr, reason), "warning")
}
