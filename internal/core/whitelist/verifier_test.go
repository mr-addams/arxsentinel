// ========================== Тесты whitelist/verifier ===================================
//   Покрывает Task 3.2 (Verify, rDNS верификация) и Task 3.5 (isFakeBot).
//
//   Все DNS-запросы идут через mockResolver — тесты детерминированы, сети не требуют.

package whitelist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Mock Resolver =============================================

// mockResolver реализует Resolver с предзаданными ответами.
// addrs: ip → список PTR hostname (rDNS)
// hosts: hostname → список IP (fDNS)
// Отсутствующий ключ → ошибка "не найдено".
type mockResolver struct {
	addrs map[string][]string
	hosts map[string][]string
}

func (m *mockResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if hostnames, ok := m.addrs[addr]; ok {
		return hostnames, nil
	}
	return nil, errors.New("no PTR record for " + addr)
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if ips, ok := m.hosts[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no A record for " + host)
}

// ========================== Фикстуры ==================================================

// googleBotCfg — конфиг-запись Googlebot для тестов.
var googleBotCfg = config.BotConfig{
	Name:         "google",
	UAPatterns:   []string{"Googlebot"},
	RDNSDomains:  []string{".googlebot.com", ".google.com"},
	VerifyMethod: "rdns",
}

// ipRangesBotCfg — бот с method=ip_ranges (Facebook/Twitter).
var ipRangesBotCfg = config.BotConfig{
	Name:         "facebook",
	UAPatterns:   []string{"facebookexternalhit"},
	RDNSDomains:  []string{},
	VerifyMethod: "ip_ranges",
}

// testIPCacheForVerifier создаёт кэш с большим TTL — не должен протухать в ходе теста.
func testIPCacheForVerifier() *IPCache {
	return NewIPCache(config.DNSCacheConfig{
		PositiveTTL:   config.Duration(time.Hour),
		NegativeTTL:   config.Duration(time.Hour),
		IPListRefresh: config.Duration(time.Hour),
	})
}

// ========================== Task 3.2 — Verify rDNS ====================================

func TestVerify_LegitimateGooglebot(t *testing.T) {
	// Сценарий: настоящий Googlebot — PTR → "crawl-66-249-66-1.googlebot.com.",
	// fDNS подтверждает IP.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "66.249.66.1", googleBotCfg)

	if !verified {
		t.Error("Verify: легитимный Googlebot должен быть verified=true")
	}
	if isFakeBot {
		t.Error("Verify: легитимный Googlebot не должен быть isFakeBot=true")
	}
}

func TestVerify_NoPTRRecord(t *testing.T) {
	// Сценарий: произвольный IP без PTR записи — не бот.
	resolver := &mockResolver{
		addrs: map[string][]string{},
		hosts: map[string][]string{},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: IP без PTR не должен быть verified")
	}
	if !isFakeBot {
		t.Error("Verify: UA совпал но DNS провалился → isFakeBot=true (Task 3.5)")
	}
}

func TestVerify_PTRWrongDomain(t *testing.T) {
	// Сценарий: PTR есть, но hostname не в googlebot.com / google.com
	resolver := &mockResolver{
		addrs: map[string][]string{
			"1.2.3.4": {"host.evil.com."},
		},
		hosts: map[string][]string{
			"host.evil.com": {"1.2.3.4"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: hostname вне rdns_domains не должен верифицироваться")
	}
	if !isFakeBot {
		t.Error("Verify: DNS fail → isFakeBot=true")
	}
}

func TestVerify_PTRCorrectDomainButFDNSMismatch(t *testing.T) {
	// Сценарий: PTR указывает на googlebot.com, но fDNS возвращает другой IP.
	// Классическая атака: выставить PTR на googlebot.com для своего IP,
	// но fDNS хоста не содержит атакующий IP.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"1.2.3.4": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}, // другой IP!
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: fDNS mismatch — IP не должен верифицироваться")
	}
	if !isFakeBot {
		t.Error("Verify: isFakeBot=true при fDNS mismatch")
	}
}

func TestVerify_MultiplePTR_OneValid(t *testing.T) {
	// Сценарий: несколько PTR-записей, одна из них валидная.
	// Достаточно одной валидной чтобы верификация прошла.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {
				"host.evil.com.",
				"crawl-66-249-66-1.googlebot.com.", // валидная
			},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "66.249.66.1", googleBotCfg)

	if !verified {
		t.Error("Verify: при наличии хотя бы одной валидной PTR — должен верифицироваться")
	}
	if isFakeBot {
		t.Error("Verify: verified=true → isFakeBot=false")
	}
}

// ========================== Task 3.2 — ip_ranges method ================================

func TestVerify_IPRangesMethod(t *testing.T) {
	// Заглушка ip_ranges: verified=false, isFakeBot=false ("неизвестно").
	// Не штрафуем реального Facebook-бота до реализации HTTP-клиента (v0.2+).
	resolver := &mockResolver{} // DNS не должен вызываться
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "69.63.176.1", ipRangesBotCfg)

	if verified {
		t.Error("Verify: ip_ranges заглушка должна возвращать verified=false (не проверяли)")
	}
	if isFakeBot {
		t.Error("Verify: ip_ranges заглушка должна возвращать isFakeBot=false (не штрафовать)")
	}
}

func TestVerify_UnknownMethod(t *testing.T) {
	// Неизвестный метод — конфиг сломан, не атака → verified=false, isFakeBot=false.
	cfg := config.BotConfig{
		Name:         "unknown",
		VerifyMethod: "magic",
	}
	resolver := &mockResolver{}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", cfg)

	if verified {
		t.Error("Verify: неизвестный метод → verified=false")
	}
	if isFakeBot {
		t.Error("Verify: неизвестный метод — конфиг сломан, не атака → isFakeBot=false")
	}
}

// ========================== Task 3.2 — кэш ============================================

func TestVerify_CacheHit_NoSecondDNS(t *testing.T) {
	// После первого Verify кэш должен содержать результат.
	// Второй вызов не должен трогать resolver (DNS не вызывается повторно).
	callCount := 0
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}

	// Обёртка для подсчёта вызовов LookupAddr
	counting := &countingResolver{inner: resolver, count: &callCount}
	v := NewVerifier(testIPCacheForVerifier(), counting, nil)

	v.Verify(context.Background(), "66.249.66.1", googleBotCfg) // первый — DNS
	v.Verify(context.Background(), "66.249.66.1", googleBotCfg) // второй — кэш

	if callCount != 1 {
		t.Errorf("Verify: LookupAddr должен вызваться 1 раз, вызван %d раз", callCount)
	}
}

// countingResolver оборачивает mockResolver и считает вызовы LookupAddr.
type countingResolver struct {
	inner *mockResolver
	count *int
}

func (c *countingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	*c.count++
	return c.inner.LookupAddr(ctx, addr)
}

func (c *countingResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return c.inner.LookupHost(ctx, host)
}

// ========================== Task 3.5 — Fake Bot ========================================

func TestVerify_FakeGooglebot_NoPTR(t *testing.T) {
	// Главный сценарий Task 3.5: UA = "Googlebot" но IP не верифицируется.
	// isFakeBot=true — pipeline должен добавить FakeBotScore.
	resolver := &mockResolver{} // нет PTR ни для одного IP
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "185.177.72.23", googleBotCfg)

	if verified {
		t.Error("FakeBot: произвольный IP не должен верифицироваться как Googlebot")
	}
	if !isFakeBot {
		t.Error("FakeBot: UA=Googlebot + DNS fail → isFakeBot=true")
	}
}

func TestVerify_FakeGooglebot_CachedResult(t *testing.T) {
	// После первого Verify(false) → кэш хранит verified=false.
	// Второй Verify должен вернуть из кэша verified=false, isFakeBot=true.
	resolver := &mockResolver{}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	v.Verify(context.Background(), "185.177.72.23", googleBotCfg) // записывает в кэш
	verified, isFakeBot := v.Verify(context.Background(), "185.177.72.23", googleBotCfg)

	if verified {
		t.Error("FakeBot cached: должен вернуть verified=false")
	}
	if !isFakeBot {
		t.Error("FakeBot cached: кэш verified=false → isFakeBot=true")
	}
}
