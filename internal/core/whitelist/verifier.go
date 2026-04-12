// ========================== Модуль whitelist/verifier ===================================
//   rDNS + fDNS верификация легитимных ботов (Googlebot, Bingbot и др.).
//   Fake bot detection: UA совпал с паттерном бота, но DNS-верификация провалена.
//
//   ЧТО ЗДЕСЬ:
//     - Resolver — интерфейс DNS-запросов (инъекция для тестируемости)
//     - Verifier — структура с кэшем и инъецированным Resolver
//     - Verify(ctx, ip, botCfg) → (verified, isFakeBot) — Task 3.2
//     - isFakeBot=true → вызывающий код добавляет FakeBotScore — Task 3.5
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Сопоставление UA → matcher.go
//     - Кэш TTL → ipcache.go
//
//   АЛГОРИТМ VERIFY (method "rdns" и "rdns_ipjson"):
//     1. Кэш-хит? → вернуть сразу
//     2. PTR lookup (rDNS): ip → hostname
//     3. Проверить suffix hostname в botCfg.RDNSDomains
//     4. A/AAAA lookup (fDNS): hostname → IPs
//     5. Убедиться что оригинальный IP есть среди A/AAAA ответов
//     6. Записать результат в кэш, вернуть
//
//   METHOD "ip_ranges":
//     Заглушка: возвращает verified=true без DNS.
//     Facebook/Twitter/Telegram публикуют IP-диапазоны — реализация в v0.2+.
//
//   FAKE BOT (Task 3.5):
//     Verify вызывается только когда MatchBot вернул matched=true.
//     Если verified=false — это фейковый бот: UA совпал, DNS провалился.
//     isFakeBot=true сигнализирует pipeline добавить cfg.Whitelist.FakeBotScore к score IP.
//
//   Реализуется: Task 3.2 (Verify) + Task 3.5 (isFakeBot).

package whitelist

import (
	"context"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Resolver интерфейс ========================================

// Resolver абстрагирует DNS-запросы для тестируемости.
// *net.Resolver удовлетворяет этому интерфейсу без изменений.
//
// Инъекция через NewVerifier — production передаёт &net.Resolver{PreferGo: true},
// тесты передают mockResolver с предопределёнными ответами.
type Resolver interface {
	// LookupAddr делает PTR-запрос (rDNS): IP → список hostname.
	// addr передаётся в формате "1.2.3.4" или "2001:db8::1".
	LookupAddr(ctx context.Context, addr string) ([]string, error)

	// LookupHost делает A/AAAA-запрос (fDNS): hostname → список IP.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ========================== Verifier ==================================================

// Verifier выполняет rDNS+fDNS верификацию IP-адресов легитимных ботов.
//
// Жизненный цикл:
//   nil      → до вызова NewVerifier
//   *Verifier → после NewVerifier, используется всё время жизни демона
//   при SIGHUP (Task 7.1) — создаётся новый экземпляр с тем же кэшем (кэш пережывает reload)
type Verifier struct {
	cache    *IPCache
	resolver Resolver
	logFn    func(tag, msg, level string) // инъекция из main.go — core/ не импортирует sys/utils
}

// NewVerifier создаёт Verifier.
// cache передаётся снаружи — при SIGHUP кэш сохраняется (не сбрасывается при reload конфига).
// resolver — *net.Resolver{PreferGo: true} в production, mock в тестах.
// logFn — utils.Log из main.go.
func NewVerifier(cache *IPCache, resolver Resolver, logFn func(tag, msg, level string)) *Verifier {
	return &Verifier{
		cache:    cache,
		resolver: resolver,
		logFn:    logFn,
	}
}

// ========================== Verify ====================================================

// Verify проверяет является ли ip легитимным ботом по botCfg.VerifyMethod.
//
// Вызывается из pipeline ТОЛЬКО когда MatchBot вернул matched=true — то есть UA
// уже совпал с паттерном бота. Задача Verify — подтвердить или опровергнуть DNS.
//
// Возвращает:
//   verified  — true если IP прошёл DNS-верификацию (легитимный бот)
//   isFakeBot — true если UA совпал с ботом, но DNS провалился (Task 3.5)
//               pipeline должен добавить cfg.Whitelist.FakeBotScore к score IP
//
// Порядок: кэш → DNS → кэш.Set → return.
// Кэш-хит избегает DNS-запросов на каждую строку лога одного IP.
func (v *Verifier) Verify(ctx context.Context, ip string, botCfg config.BotConfig) (verified bool, isFakeBot bool) {
	// ── Кэш-хит ──────────────────────────────────────────────────────────────────────
	// isFakeBot читается из кэша напрямую — нельзя выводить через !verified:
	// для ip_ranges ботов verified=false означает "не проверялся", isFakeBot=false.
	if cachedVerified, cachedIsFakeBot, ok := v.cache.Get(ip); ok {
		return cachedVerified, cachedIsFakeBot
	}

	// ── DNS-верификация ───────────────────────────────────────────────────────────────
	switch botCfg.VerifyMethod {
	case "rdns", "rdns_ipjson":
		// rdns_ipjson отличается только проверкой IP-диапазонов через Google JSON API.
		// HTTP-клиент для этого — v0.2+. Сейчас rdns_ipjson обрабатывается как rdns.
		verified = v.verifyRDNS(ctx, ip, botCfg)
		// UA совпал с паттерном бота (Verify вызывается только при matched=true),
		// DNS провалился → это фейковый бот → начислить FakeBotScore.
		isFakeBot = !verified
	case "ip_ranges":
		// KNOWN LIMITATION (v0.2+): IP-диапазоны Facebook/Twitter/Telegram требуют
		// HTTP-клиента для загрузки актуальных диапазонов.
		// До реализации — возвращаем verified=false, isFakeBot=false ("неизвестно"):
		//   verified=true  было бы ложью — диапазоны не проверены.
		//   isFakeBot=true было бы несправедливым штрафом — реальный Facebook-бот
		//   не должен получать FakeBotScore только из-за незавершённой реализации.
		verified = false
		isFakeBot = false
	default:
		// Неизвестный метод — не верифицируем, не штрафуем (конфиг сломан, не атака).
		if v.logFn != nil {
			v.logFn("WHITELIST", "неизвестный verify_method: "+botCfg.VerifyMethod+" для бота "+botCfg.Name, "warn")
		}
		verified = false
		isFakeBot = false
	}

	// ── Сохраняем в кэш и возвращаем ─────────────────────────────────────────────────
	v.cache.Set(ip, verified, isFakeBot)
	return verified, isFakeBot
}

// ========================== rDNS верификация ==========================================

// verifyRDNS выполняет двухшаговую DNS-верификацию:
//   Шаг 1 (rDNS): IP → PTR → hostname
//   Шаг 2 (fDNS): hostname → A/AAAA → должен содержать оригинальный IP
//
// Оба шага необходимы: только PTR недостаточно — PTR-запись может выставить
// кто угодно для своего IP. Обратная проверка (fDNS) подтверждает что хост
// действительно резолвится обратно в этот IP.
//
// Дополнительно проверяется suffix hostname в botCfg.RDNSDomains:
//   Googlebot → ".googlebot.com" или ".google.com"
//   Bingbot   → ".search.msn.com"
// Без этой проверки злоумышленник мог бы создать PTR вида "evil.com" → IP,
// A: IP → "evil.com", и пройти двойную проверку не будучи Googlebot.
func (v *Verifier) verifyRDNS(ctx context.Context, ip string, botCfg config.BotConfig) bool {
	// ── Шаг 1: PTR lookup ─────────────────────────────────────────────────────────────
	hostnames, err := v.resolver.LookupAddr(ctx, ip)
	if err != nil || len(hostnames) == 0 {
		if v.logFn != nil {
			v.logFn("WHITELIST", "PTR fail для "+ip+": нет PTR записи", "debug")
		}
		return false
	}

	// Перебираем все PTR-записи — IP может иметь несколько hostname.
	// Достаточно одного валидного hostname чтобы верификация прошла.
	for _, hostname := range hostnames {
		// Нормализация: net.LookupAddr возвращает hostname с точкой на конце ("foo.google.com.")
		hostname = strings.TrimSuffix(hostname, ".")

		// ── Проверка rDNS domain suffix ───────────────────────────────────────────────
		if !matchesRDNSDomain(hostname, botCfg.RDNSDomains) {
			continue
		}

		// ── Шаг 2: A/AAAA lookup (fDNS) ──────────────────────────────────────────────
		addrs, err := v.resolver.LookupHost(ctx, hostname)
		if err != nil {
			if v.logFn != nil {
				v.logFn("WHITELIST", "fDNS fail для "+hostname+": "+err.Error(), "debug")
			}
			continue
		}

		// Проверяем что оригинальный IP есть среди A/AAAA ответов
		for _, addr := range addrs {
			if addr == ip {
				if v.logFn != nil {
					v.logFn("WHITELIST", "верифицирован "+ip+" как "+botCfg.Name+" ("+hostname+")", "debug")
				}
				return true
			}
		}
	}

	if v.logFn != nil {
		v.logFn("WHITELIST", "верификация провалена для "+ip+" (бот: "+botCfg.Name+")", "debug")
	}
	return false
}

// matchesRDNSDomain проверяет что hostname оканчивается на один из допустимых rDNS-суффиксов.
//
// Пустой список RDNSDomains (как у ip_ranges ботов) — метод не вызывается для них,
// но защитная проверка есть: пустой список → false (не пропускаем без проверки).
func matchesRDNSDomain(hostname string, domains []string) bool {
	for _, domain := range domains {
		if strings.HasSuffix(hostname, domain) {
			return true
		}
	}
	return false
}
