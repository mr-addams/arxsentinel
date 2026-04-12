// ========================== Модуль whitelist/matcher ====================================
//   Сопоставление UA с паттернами легитимных ботов и custom whitelist по IP/CIDR/UA.
//
//   ЧТО ЗДЕСЬ:
//     - Matcher — структура, инициализируется один раз из конфига
//     - MatchBot(ua) → (botName, botCfg, matched) — Task 3.1
//     - IsWhitelistedIP(ip) bool   — custom whitelist по IP и CIDR — Task 3.4
//     - IsWhitelistedUA(ua) bool   — custom whitelist по UA-подстроке — Task 3.4
//
//   ЧТО НЕ ЗДЕСЬ:
//     - DNS-верификация → verifier.go (Tasks 3.2, 3.5)
//     - Кэш результатов → ipcache.go (Task 3.3)
//
//   АЛГОРИТМ MatchBot:
//     Перебор ботов из конфига, для каждого — перебор UAPatterns.
//     strings.Contains — case-sensitive (UA ботов имеют фиксированный регистр).
//     Первое совпадение побеждает — порядок ботов в конфиге задаёт приоритет.
//
//   АЛГОРИТМ IsWhitelistedIP:
//     1. Точное совпадение в map[string]struct{} — O(1)
//     2. Перебор предкомпилированных *net.IPNet — O(n) по числу CIDR
//     Предкомпиляция в NewMatcher: net.ParseCIDR вызывается один раз при старте.
//
//   Реализуется: Task 3.1 (MatchBot) + Task 3.4 (IsWhitelistedIP, IsWhitelistedUA).

package whitelist

import (
	"fmt"
	"net"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Matcher ===================================================

// Matcher хранит предобработанные данные для быстрого сопоставления UA/IP/CIDR.
//
// Жизненный цикл:
//   nil      → до вызова NewMatcher
//   *Matcher → после NewMatcher, используется до завершения демона
//   перестройка → при SIGHUP (Task 7.1) — создаётся новый экземпляр
type Matcher struct {
	bots []config.BotConfig // список ботов из конфига — порядок задаёт приоритет совпадения

	// custom whitelist — предобработанные для O(1) / O(n) lookup
	customIPs    map[string]struct{} // точные IP-адреса
	customCIDRs  []*net.IPNet        // предкомпилированные подсети
	customUASubs []string            // UA-подстроки (используются в strings.Contains)
}

// NewMatcher создаёт Matcher из конфига.
// Возвращает ошибку если любой CIDR из whitelist.custom.cidrs невалиден.
// Вызывается из main.go при старте и при SIGHUP.
func NewMatcher(cfg config.WhitelistConfig) (*Matcher, error) {
	// ── Предкомпиляция CIDR ───────────────────────────────────────────────────────────
	// net.ParseCIDR вызывается один раз при старте — дорогой парсинг убран из hot path.
	cidrs := make([]*net.IPNet, 0, len(cfg.Custom.CIDRs))
	for _, cidr := range cfg.Custom.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("невалидный CIDR в whitelist.custom.cidrs %q: %w", cidr, err)
		}
		cidrs = append(cidrs, ipNet)
	}

	// ── Индекс точных IP — O(1) lookup ────────────────────────────────────────────────
	// map[string]struct{} вместо slice: каждый IP проверяется на каждой строке лога.
	ips := make(map[string]struct{}, len(cfg.Custom.IPs))
	for _, ip := range cfg.Custom.IPs {
		ips[ip] = struct{}{}
	}

	// Копируем slice заголовки — не разделяем underlying array с конфигом.
	// При SIGHUP (Task 7.1) создаётся новый экземпляр Matcher из нового конфига;
	// старый Matcher продолжает работать пока pipeline не переключится.
	// Если не копировать — старый и новый Matcher могут читать один underlying array.
	// BotConfig содержит только строки и []string — Go-строки иммутабельны, глубокое
	// копирование не нужно; копируем только верхний уровень slice.
	bots := append([]config.BotConfig(nil), cfg.Bots...)
	uaSubs := append([]string(nil), cfg.Custom.UASubstrings...)

	return &Matcher{
		bots:         bots,
		customIPs:    ips,
		customCIDRs:  cidrs,
		customUASubs: uaSubs,
	}, nil
}

// ========================== Task 3.1 — UA Matcher =====================================

// MatchBot проверяет UA на совпадение с паттернами легитимных ботов из конфига.
//
// Возвращает:
//   botName — идентификатор бота (например "google", "bing")
//   botCfg  — полная конфиг-запись бота (нужна Verifier-у для rdns_domains и verify_method)
//   matched — true если найдено совпадение
//
// Алгоритм: strings.Contains, case-sensitive — UA поисковых ботов имеют зафиксированный
// регистр в документации (RFC-подобные спецификации каждого вендора).
// При пустом UA возвращает matched=false немедленно — нет смысла перебирать паттерны.
func (m *Matcher) MatchBot(ua string) (botName string, botCfg config.BotConfig, matched bool) {
	if ua == "" {
		return "", config.BotConfig{}, false
	}
	for _, bot := range m.bots {
		for _, pattern := range bot.UAPatterns {
			if strings.Contains(ua, pattern) {
				return bot.Name, bot, true
			}
		}
	}
	return "", config.BotConfig{}, false
}

// ========================== Task 3.4 — Custom Whitelist ================================

// IsWhitelistedIP возвращает true если ip находится в custom whitelist (точный IP или CIDR).
//
// Порядок проверок:
//   1. Точное совпадение — O(1) map lookup
//   2. CIDR — O(n) по предкомпилированным подсетям
// Точная проверка идёт первой: большинство whitelist содержат единичные IP, не подсети.
//
// Невалидный ip (не парсится net.ParseIP) не матчит ни один CIDR — возвращает false.
func (m *Matcher) IsWhitelistedIP(ip string) bool {
	// ── Точное совпадение ─────────────────────────────────────────────────────────────
	if _, ok := m.customIPs[ip]; ok {
		return true
	}

	// ── Проверка по CIDR ──────────────────────────────────────────────────────────────
	if len(m.customCIDRs) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Невалидный IP не может входить ни в одну подсеть
		return false
	}
	for _, cidr := range m.customCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsWhitelistedUA возвращает true если ua содержит любую из custom UA-подстрок.
//
// Case-sensitive — кастомный whitelist предполагает точно известные UA мониторингов,
// load balancer health-check'ов и внутренних сервисов. Нечёткое совпадение создаёт
// риск случайного пропуска сканеров с похожим UA.
func (m *Matcher) IsWhitelistedUA(ua string) bool {
	if ua == "" {
		return false
	}
	for _, sub := range m.customUASubs {
		if strings.Contains(ua, sub) {
			return true
		}
	}
	return false
}
