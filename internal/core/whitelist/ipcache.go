// ========================== Модуль whitelist/ipcache ====================================
//   Кэш результатов DNS-верификации с раздельными TTL для positive/negative результатов.
//   Предотвращает повторные DNS-запросы для уже проверенных IP.
//
//   ЧТО ЗДЕСЬ:
//     - IPCache — in-memory кэш с TTL expiry
//     - Positive TTL (verified=true) >> Negative TTL (verified=false)
//     - Lazy expiry: истёкшие записи удаляются при Get, не фоновой горутиной
//
//   ЧТО НЕ ЗДЕСЬ:
//     - DNS-запросы → verifier.go
//     - Сопоставление UA/IP → matcher.go
//
//   LAZY EXPIRY vs фоновый GC:
//     IPCache хранит только боты — сотни IP, не тысячи.
//     Фоновая горутина добавляет сложность (shutdown, sync) без ощутимой пользы.
//     Expired записи вытесняются при следующем Get — достаточно для этого масштаба.
//
//   Реализуется: Task 3.3.

package whitelist

import (
	"sync"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== IPCache ===================================================

// cacheEntry — одна запись кэша: результат верификации + срок действия.
// isFakeBot хранится явно — нельзя выводить из !verified:
// для ip_ranges ботов verified=false означает "не проверялся", а не "провалил DNS".
type cacheEntry struct {
	verified  bool
	isFakeBot bool
	expiresAt time.Time
}

// IPCache кэширует результаты DNS-верификации IP-адресов ботов.
//
// Жизненный цикл записи:
//   miss      → Get возвращает ok=false → Verifier делает DNS-запрос → Set
//   hit       → Get возвращает verified, ok=true
//   expired   → Get удаляет запись, возвращает ok=false → повторная верификация
type IPCache struct {
	mu          sync.RWMutex
	entries     map[string]cacheEntry
	positiveTTL time.Duration // TTL для verified=true (легитимный бот)
	negativeTTL time.Duration // TTL для verified=false (фейк или неизвестно)
}

// NewIPCache создаёт IPCache из конфига.
// Вызывается из main.go при старте и при SIGHUP (Task 7.1).
func NewIPCache(cfg config.DNSCacheConfig) *IPCache {
	return &IPCache{
		entries:     make(map[string]cacheEntry),
		positiveTTL: time.Duration(cfg.PositiveTTL),
		negativeTTL: time.Duration(cfg.NegativeTTL),
	}
}

// ========================== Get =======================================================

// Get возвращает результат верификации из кэша.
//
// ok=false означает кэш-промах: запись отсутствует или истекла.
// При истёкшей записи — удаляем её под write-lock, чтобы следующий запрос
// не нашёл её снова (lazy expiry).
//
// Двухфазный lock (RLock → Lock при expiry):
//   Большинство вызовов — hit по живой записи → только RLock.
//   Только при expiry переходим к write lock — редкий случай.
func (c *IPCache) Get(ip string) (verified bool, isFakeBot bool, ok bool) {
	// ── Быстрый путь: read lock ────────────────────────────────────────────────────────
	c.mu.RLock()
	entry, found := c.entries[ip]
	c.mu.RUnlock()

	if !found {
		return false, false, false
	}

	if !time.Now().After(entry.expiresAt) {
		return entry.verified, entry.isFakeBot, true
	}

	// ── Slow path: запись найдена но истекла — удаляем под write lock ────────────────
	c.mu.Lock()
	// Повторная проверка после получения write lock: между RUnlock и Lock
	// concurrent Set мог обновить запись с новым expiresAt — не удаляем живую запись.
	// Если запись жива — возвращаем свежее значение вместо miss (TOCTOU fix).
	if e, still := c.entries[ip]; still {
		if !time.Now().After(e.expiresAt) {
			// Set успел обновить запись — возвращаем свежее значение вместо miss.
			c.mu.Unlock()
			return e.verified, e.isFakeBot, true
		}
		delete(c.entries, ip)
	}
	c.mu.Unlock()
	return false, false, false
}

// ========================== Set =======================================================

// Set сохраняет результат верификации в кэш с TTL в зависимости от verified.
//
// Positive TTL (verified=true) больше negative (verified=false):
//   - Легитимный бот меняет IP редко → долгий кэш снижает DNS-нагрузку.
//   - Фейк или неизвестный IP → короткий кэш, чтобы повторная попытка
//     верифицировалась заново (IP мог переехать к боту).
//
// isFakeBot хранится явно — не выводится из !verified при Get.
// Это важно для ip_ranges ботов: verified=false там означает "не проверялся",
// а не "провалил DNS", поэтому isFakeBot для них должен быть false.
func (c *IPCache) Set(ip string, verified bool, isFakeBot bool) {
	ttl := c.negativeTTL
	if verified {
		ttl = c.positiveTTL
	}

	c.mu.Lock()
	c.entries[ip] = cacheEntry{
		verified:  verified,
		isFakeBot: isFakeBot,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}
