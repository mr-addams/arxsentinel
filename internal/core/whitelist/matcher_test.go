// ========================== Тесты whitelist/matcher ====================================
//   Покрывает Task 3.1 (MatchBot) и Task 3.4 (IsWhitelistedIP, IsWhitelistedUA).
//
//   Тестовые данные:
//     - Конфиг с двумя ботами: google (Googlebot, AdsBot-Google) и bing (bingbot)
//     - Custom whitelist: IP "10.0.0.1", CIDR "192.168.1.0/24", UA-подстрока "healthcheck"

package whitelist

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Фикстуры ==================================================

// testConfig возвращает минимальный конфиг с двумя ботами и custom whitelist.
// Вынесен в helper — все тесты используют единую базу, изменения в одном месте.
func testConfig() config.WhitelistConfig {
	return config.WhitelistConfig{
		Bots: []config.BotConfig{
			{
				Name:        "google",
				UAPatterns:  []string{"Googlebot", "AdsBot-Google"},
				RDNSDomains: []string{".googlebot.com", ".google.com"},
			},
			{
				Name:        "bing",
				UAPatterns:  []string{"bingbot"},
				RDNSDomains: []string{".search.msn.com"},
			},
		},
		Custom: config.CustomWhitelistConfig{
			IPs:          []string{"10.0.0.1"},
			CIDRs:        []string{"192.168.1.0/24"},
			UASubstrings: []string{"healthcheck", "monitoring"},
		},
	}
}

// mustNewMatcher создаёт Matcher из тестового конфига.
// t.Fatal при ошибке — тест не может продолжаться без валидного Matcher.
func mustNewMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher(testConfig())
	if err != nil {
		t.Fatalf("NewMatcher: неожиданная ошибка: %v", err)
	}
	return m
}

// ========================== NewMatcher ================================================

func TestNewMatcher_ValidConfig(t *testing.T) {
	m := mustNewMatcher(t)
	if m == nil {
		t.Fatal("NewMatcher вернул nil")
	}
}

func TestNewMatcher_InvalidCIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.CIDRs = []string{"not-a-cidr"}
	_, err := NewMatcher(cfg)
	if err == nil {
		t.Fatal("NewMatcher должен вернуть ошибку для невалидного CIDR")
	}
}

func TestNewMatcher_EmptyBots(t *testing.T) {
	// Пустой список ботов — не ошибка, просто MatchBot всегда вернёт false
	cfg := testConfig()
	cfg.Bots = nil
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher с пустыми ботами: %v", err)
	}
	_, _, matched := m.MatchBot("Googlebot/2.1")
	if matched {
		t.Error("MatchBot: при пустом списке ботов должен вернуть matched=false")
	}
}

// ========================== Task 3.1 — MatchBot =======================================

func TestMatchBot_GoogleUA(t *testing.T) {
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("Googlebot/2.1 (+http://www.google.com/bot.html)")
	if !matched {
		t.Error("MatchBot: Googlebot должен совпадать")
	}
	if botName != "google" {
		t.Errorf("MatchBot: ожидался бот %q, получен %q", "google", botName)
	}
}

func TestMatchBot_AdsBotGoogle(t *testing.T) {
	// AdsBot-Google — второй паттерн google-бота
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("AdsBot-Google (+http://www.google.com/adsbot.html)")
	if !matched {
		t.Error("MatchBot: AdsBot-Google должен совпадать")
	}
	if botName != "google" {
		t.Errorf("MatchBot: ожидался %q, получен %q", "google", botName)
	}
}

func TestMatchBot_Bingbot(t *testing.T) {
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")
	if !matched {
		t.Error("MatchBot: bingbot должен совпадать")
	}
	if botName != "bing" {
		t.Errorf("MatchBot: ожидался %q, получен %q", "bing", botName)
	}
}

func TestMatchBot_BotCfgReturned(t *testing.T) {
	// Verifier (Task 3.2) использует botCfg.RDNSDomains и VerifyMethod —
	// убеждаемся что возвращается правильная конфиг-запись, а не нулевая структура
	m := mustNewMatcher(t)
	_, botCfg, matched := m.MatchBot("Googlebot/2.1")
	if !matched {
		t.Fatal("MatchBot: Googlebot не совпал")
	}
	if len(botCfg.RDNSDomains) == 0 {
		t.Error("MatchBot: botCfg.RDNSDomains не должен быть пустым для google")
	}
}

func TestMatchBot_CurlNotMatched(t *testing.T) {
	// curl — не легитимный бот, не должен совпадать
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("curl/8.7.1")
	if matched {
		t.Error("MatchBot: curl не должен совпадать")
	}
}

func TestMatchBot_EmptyUA(t *testing.T) {
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("")
	if matched {
		t.Error("MatchBot: пустой UA не должен совпадать")
	}
}

func TestMatchBot_ArbitraryUA(t *testing.T) {
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if matched {
		t.Error("MatchBot: обычный браузерный UA не должен совпадать")
	}
}

func TestMatchBot_CaseSensitive(t *testing.T) {
	// "googlebot" в нижнем регистре — не совпадает (паттерн "Googlebot" с заглавной)
	// Реальные Googlebot пишут "Googlebot" с заглавной — это контракт Google.
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("googlebot/2.1")
	if matched {
		t.Error("MatchBot: совпадение должно быть case-sensitive, 'googlebot' не должен матчить паттерн 'Googlebot'")
	}
}

// ========================== Task 3.4 — IsWhitelistedIP ================================

func TestIsWhitelistedIP_ExactMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedIP("10.0.0.1") {
		t.Error("IsWhitelistedIP: IP 10.0.0.1 должен быть в whitelist")
	}
}

func TestIsWhitelistedIP_ExactNoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("10.0.0.2") {
		t.Error("IsWhitelistedIP: IP 10.0.0.2 не должен быть в whitelist")
	}
}

func TestIsWhitelistedIP_CIDRMatch(t *testing.T) {
	m := mustNewMatcher(t)
	// 192.168.1.100 входит в 192.168.1.0/24
	if !m.IsWhitelistedIP("192.168.1.100") {
		t.Error("IsWhitelistedIP: 192.168.1.100 должен входить в CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_CIDRBoundary(t *testing.T) {
	m := mustNewMatcher(t)
	// .1 — первый хост в /24 (сетевой адрес .0 не хост, но net.IPNet.Contains его вернёт)
	if !m.IsWhitelistedIP("192.168.1.1") {
		t.Error("IsWhitelistedIP: 192.168.1.1 должен входить в CIDR 192.168.1.0/24")
	}
	// .254 — последний хост в /24
	if !m.IsWhitelistedIP("192.168.1.254") {
		t.Error("IsWhitelistedIP: 192.168.1.254 должен входить в CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_CIDRNoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	// 192.168.2.1 — другая подсеть
	if m.IsWhitelistedIP("192.168.2.1") {
		t.Error("IsWhitelistedIP: 192.168.2.1 не должен входить в CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_InvalidIP(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("not-an-ip") {
		t.Error("IsWhitelistedIP: невалидный IP не должен матчить")
	}
}

func TestIsWhitelistedIP_EmptyIP(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("") {
		t.Error("IsWhitelistedIP: пустой IP не должен матчить")
	}
}

// ========================== Task 3.4 — IsWhitelistedUA ================================

func TestIsWhitelistedUA_Healthcheck(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedUA("my-healthcheck/1.0") {
		t.Error("IsWhitelistedUA: UA с подстрокой 'healthcheck' должен матчить")
	}
}

func TestIsWhitelistedUA_Monitoring(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedUA("Prometheus monitoring-agent/2.3") {
		t.Error("IsWhitelistedUA: UA с подстрокой 'monitoring' должен матчить")
	}
}

func TestIsWhitelistedUA_NoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedUA("Mozilla/5.0 (compatible; Googlebot/2.1)") {
		t.Error("IsWhitelistedUA: Googlebot UA не содержит кастомных подстрок")
	}
}

func TestIsWhitelistedUA_EmptyUA(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedUA("") {
		t.Error("IsWhitelistedUA: пустой UA не должен матчить")
	}
}

func TestIsWhitelistedUA_EmptySubstrings(t *testing.T) {
	// Нет кастомных UA-подстрок в конфиге — ничего не матчит
	cfg := testConfig()
	cfg.Custom.UASubstrings = nil
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: неожиданная ошибка: %v", err)
	}
	if m.IsWhitelistedUA("healthcheck") {
		t.Error("IsWhitelistedUA: при пустом списке подстрок не должно быть совпадений")
	}
}
