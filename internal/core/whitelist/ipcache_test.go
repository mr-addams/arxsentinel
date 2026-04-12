// ========================== Тесты whitelist/ipcache ====================================
//   Покрывает Task 3.3: Get (miss, hit, expiry), Set (positive/negative TTL).

package whitelist

import (
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// testCacheConfig возвращает конфиг кэша с короткими TTL для тестов.
// Короткие TTL позволяют проверять expiry без долгого sleep.
func testCacheConfig() config.DNSCacheConfig {
	return config.DNSCacheConfig{
		PositiveTTL:   config.Duration(100 * time.Millisecond),
		NegativeTTL:   config.Duration(50 * time.Millisecond),
		IPListRefresh: config.Duration(time.Hour),
	}
}

// ========================== Get — miss ================================================

func TestIPCache_GetMiss_NotFound(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: должен вернуть ok=false для отсутствующего IP")
	}
}

// ========================== Set + Get — hit ===========================================

func TestIPCache_SetGet_Verified(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: должен вернуть ok=true после Set")
	}
	if !verified {
		t.Error("Get: должен вернуть verified=true")
	}
	if isFakeBot {
		t.Error("Get: должен вернуть isFakeBot=false")
	}
}

func TestIPCache_SetGet_NotVerified(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: должен вернуть ok=true после Set")
	}
	if verified {
		t.Error("Get: должен вернуть verified=false")
	}
	if !isFakeBot {
		t.Error("Get: должен вернуть isFakeBot=true")
	}
}

func TestIPCache_SetGet_IPRanges(t *testing.T) {
	// ip_ranges бот: verified=false, isFakeBot=false — "неизвестно", не штраф
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, false)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: должен вернуть ok=true после Set")
	}
	if verified {
		t.Error("Get: verified=false для ip_ranges бота")
	}
	if isFakeBot {
		t.Error("Get: isFakeBot=false для ip_ranges бота — не штрафовать")
	}
}

// ========================== TTL expiry ================================================

func TestIPCache_PositiveTTLExpiry(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)

	// Ждём истечения positive TTL (100ms)
	time.Sleep(120 * time.Millisecond)

	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: запись должна истечь после positive TTL")
	}
}

func TestIPCache_NegativeTTLExpiry(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)

	// Ждём истечения negative TTL (50ms) — он короче positive
	time.Sleep(70 * time.Millisecond)

	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: negative запись должна истечь раньше positive")
	}
}

func TestIPCache_PositiveOutlivesNegative(t *testing.T) {
	// positive TTL=100ms, negative TTL=50ms
	// Проверяем что positive запись ещё жива когда negative уже истекла
	c := NewIPCache(testCacheConfig())
	c.Set("pos.ip", true, false)
	c.Set("neg.ip", false, true)

	time.Sleep(70 * time.Millisecond) // negative истёк, positive ещё жив

	if _, _, ok := c.Get("neg.ip"); ok {
		t.Error("Get: negative запись должна истечь через 50ms")
	}
	if _, _, ok := c.Get("pos.ip"); !ok {
		t.Error("Get: positive запись должна быть жива через 70ms (TTL=100ms)")
	}
}

// ========================== Overwrite =================================================

func TestIPCache_OverwriteEntry(t *testing.T) {
	// Set дважды для одного IP — последнее значение побеждает
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)
	c.Set("1.2.3.4", true, false) // перезаписываем

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: должен вернуть ok=true")
	}
	if !verified {
		t.Error("Get: должен вернуть verified=true после перезаписи")
	}
	if isFakeBot {
		t.Error("Get: должен вернуть isFakeBot=false после перезаписи")
	}
}

// ========================== Lazy expiry удаляет запись ================================

func TestIPCache_ExpiredEntryRemoved(t *testing.T) {
	// После Get по истёкшей записи — она должна быть удалена из map.
	// Косвенная проверка: повторный Get должен вернуть ok=false (не старое значение).
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)
	time.Sleep(120 * time.Millisecond) // TTL истёк

	_, _, ok1 := c.Get("1.2.3.4") // первый Get — удаляет истёкшую запись
	_, _, ok2 := c.Get("1.2.3.4") // второй Get — miss (запись удалена)

	if ok1 || ok2 {
		t.Error("Get: истёкшая запись не должна возвращаться")
	}
}
