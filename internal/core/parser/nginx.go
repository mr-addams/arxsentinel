// ========================== Модуль parser/nginx =========================================
//   Парсер combined log format + поле real_ip.
//   Извлекает структурированный LogEntry из строки лога Nginx.
//
//   ЧТО ЗДЕСЬ:
//     - LogEntry — все поля строки лога + производные (Path, Query, RealIP)
//     - Parse(line) — парсинг одной строки, graceful skip при битой строке
//     - extractRealIP() — последний IP из цепочки X-Forwarded-For в поле real_ip
//
//   Формат лога (combined + real_ip):
//     $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//     "$http_referer" "$http_user_agent" "$real_ip"
//
//   Пример строки:
//     20.48.232.178 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/2.0" 200 66088 "-" "-" "20.48.232.178"
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Логирование (sys/utils) — вызывающая сторона решает, как логировать пропуски
//     - Агрегация состояния (core/state)

package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ========================== Вспомогательные константы ===================================

// logLineRe — регулярное выражение для nginx combined log format + поле real_ip.
//
// Используем [^"]* вместо .* внутри кавычек и [^\]]* для времени — гарантирует O(n)
// без катастрофического backtracking на аномально длинных строках (overflow атаки).
//
// Группы захвата:
//
//	[1] remote_addr   [2] remote_user  [3] time_local    [4] request
//	[5] status        [6] bytes_sent   [7] http_referer  [8] http_user_agent  [9] real_ip
var logLineRe = regexp.MustCompile(
	`^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)"$`,
)

// nginxTimeLayout — формат времени nginx (time_local) для time.Parse.
// Пример: 02/Apr/2026:00:26:49 +0000
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// ========================== Структура LogEntry ==========================================

// LogEntry — структурированная запись одной строки nginx access.log.
//
// RealIP — предпочтительный IP клиента: либо из поля $real_ip (последний в цепочке),
// либо RemoteAddr если $real_ip не установлен. Используется всеми детекторами.
// RemoteAddr остаётся для аудита (может быть адресом балансировщика).
type LogEntry struct {
	RemoteAddr string    // $remote_addr — адрес TCP-соединения (может быть nginx-proxy или балансировщик)
	RemoteUser string    // $remote_user — Basic Auth user; "-" если анонимный запрос
	Time       time.Time // $time_local — время начала обработки запроса на сервере
	Method     string    // из $request — HTTP-метод (GET, POST, HEAD, ...)
	RawURI     string    // из $request — полный URI включая query string; используется overflow-детектором для замера длины
	Path       string    // из $request — путь без query string; используется probe-детектором и state-трекером
	Query      string    // из $request — query string без "?"; используется overflow-детектором для анализа параметров
	Protocol   string    // из $request — версия HTTP (HTTP/1.1, HTTP/2.0, HTTP/3.0)
	Status     int       // $status — HTTP-код ответа
	BytesSent  int64     // $body_bytes_sent — байт тела ответа (0 для HEAD и 304)
	Referer    string    // $http_referer — строка как есть; "-" если отсутствует
	UserAgent  string    // $http_user_agent — строка как есть; "-" если отсутствует
	RealIP     string    // последний IP из $real_ip; == RemoteAddr если поле real_ip == "-"
}

// ========================== Публичный API ===============================================

// Parse парсит одну строку nginx combined log format + real_ip.
// Возвращает (entry, true) при успехе, (nil, false) при невалидной строке.
//
// Вызывается pipeline'ом для каждой строки из tail-reader'а.
// Bitые строки (бинарный мусор, обрезанные строки, нестандартный формат) пропускаются
// без паники — логирование пропуска остаётся на усмотрение вызывающей стороны.
func Parse(line string) (*LogEntry, bool) {
	m := logLineRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}

	// m[1]=remote_addr, m[2]=remote_user, m[3]=time_local, m[4]=request,
	// m[5]=status, m[6]=bytes_sent, m[7]=referer, m[8]=user_agent, m[9]=real_ip

	// ── Парсинг времени ────────────────────────────────────────────────────────────────
	t, err := time.Parse(nginxTimeLayout, m[3])
	if err != nil {
		// Невалидная дата означает битую строку — не просто неожиданный формат
		return nil, false
	}

	// ── Числовые поля ─────────────────────────────────────────────────────────────────
	status, err := strconv.Atoi(m[5])
	if err != nil {
		return nil, false
	}

	bytes, err := strconv.ParseInt(m[6], 10, 64)
	if err != nil {
		return nil, false
	}

	// ── Request: метод + URI + протокол ───────────────────────────────────────────────
	method, rawURI, proto := splitRequest(m[4])

	path, query := splitURI(rawURI)

	// ── RealIP: последний IP в цепочке X-Forwarded-For ────────────────────────────────
	realIP := extractRealIP(m[9], m[1])

	return &LogEntry{
		RemoteAddr: m[1],
		RemoteUser: m[2],
		Time:       t,
		Method:     method,
		RawURI:     rawURI,
		Path:       path,
		Query:      query,
		Protocol:   proto,
		Status:     status,
		BytesSent:  bytes,
		Referer:    m[7],
		UserAgent:  m[8],
		RealIP:     realIP,
	}, true
}

// ========================== Вспомогательные функции =====================================

// splitRequest разбивает строку $request на метод, полный URI и протокол.
// Стандартный формат: "METHOD /path?query HTTP/x.y"
//
// URI намеренно берётся как parts[1] (не всё между методом и протоколом),
// т.к. nginx логирует URI без пробелов — space-in-URI крайне редки и не поддерживаются.
// При нестандартном формате (менее 3 частей) возвращаем весь request как метод,
// чтобы entry был видим в логах для ручного разбора.
func splitRequest(req string) (method, uri, proto string) {
	parts := strings.SplitN(req, " ", 3)
	if len(parts) != 3 {
		return req, "", ""
	}
	return parts[0], parts[1], parts[2]
}

// splitURI разделяет URI на path и query string.
// "/path?key=val&foo=bar" → ("/path", "key=val&foo=bar")
// "/path"                 → ("/path", "")
func splitURI(uri string) (path, query string) {
	idx := strings.IndexByte(uri, '?')
	if idx < 0 {
		return uri, ""
	}
	return uri[:idx], uri[idx+1:]
}

// extractRealIP извлекает реальный IP клиента из поля $real_ip.
//
// Поле может содержать цепочку X-Forwarded-For вида "127.0.0.1, 185.177.72.23":
// первый IP — от клиента (может быть spoofed), последний — добавлен доверенным proxy.
// Берём последний элемент как наиболее достоверный источник.
//
// При $real_ip == "-" (модуль ngx_realip не настроен) — используем RemoteAddr напрямую.
func extractRealIP(realIP, remoteAddr string) string {
	if realIP == "" || realIP == "-" {
		// Модуль real_ip не установлен или не настроен — fallback на TCP-адрес
		return remoteAddr
	}
	if idx := strings.LastIndexByte(realIP, ','); idx >= 0 {
		// Цепочка: "ip1, ip2, ip3" → берём ip3 и убираем пробелы
		return strings.TrimSpace(realIP[idx+1:])
	}
	return realIP
}
