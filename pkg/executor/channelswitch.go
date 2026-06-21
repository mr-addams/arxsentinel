// ========================== pkg/executor — Named Channel Switch =============================
//   In-process singleton соединяет именованные Sink-очереди с Executor-источниками.
//   Pipeline-sink вызывает AttachWriter(name, bufferSize) → получает Queue для Push.
//   Executor вызывает AttachReader(name) → получает Queue, вызывает Pop(ctx).
//   При shutdown pipeline вызывает DetachWriter(name) → Queue.Close() и удаление из карты.
//
//   ЧТО ЗДЕСЬ:
//     NamedChannelSwitch — глобальный singleton за пакетными функциями
//     AttachWriter         — создать именованную MemoryQueue, вернуть Queue для Push
//     AttachWriterWithQueue — зарегистрировать произвольную Queue (для bbolt/redis)
//     RegisterSinkFromConfig — создать Queue из QueueConfig (bbolt/redis/memory) и зарегистрировать
//     AttachReader         — вернуть Queue для Pop
//     DetachWriter         — закрыть Queue и удалить из карты
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     Жизненный цикл Executor'а — в main.go (AttachReader + Run())
//     Жизненный цикл Pipeline — в pipeline (AttachWriter + Write)
//
//   ПОЧЕМУ SINGLETON:
//     Никакого DI-фреймворка, никаких middleware, никакого config-wiring.
//     Два места вызова (pipeline и executor), которые никогда не импортируют друг друга.
//     Singleton — простейший корректный мост.
//
//   THREAD SAFETY:
//     RWMutex — AttachWriter/AttachWriterWithQueue/DetachWriter берут write-лок,
//     AttachReader берёт read-лок.

package executor

import (
	"fmt"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/pkg/logger"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// DefaultBufferSize используется при вызове AttachWriter с bufferSize <= 0.
const DefaultBufferSize = 1000

var (
	ncsMu     sync.RWMutex
	ncsQueues = map[string]queue.Queue{}
	// ncsRefs считает, сколько sink'ов разделяют одну именованную очередь.
	// DetachWriter закрывает очередь только когда последний sink дерегистрируется.
	ncsRefs = map[string]int{}
)

// AttachWriter возвращает MemoryQueue для указанного имени, создавая её при необходимости.
// Fan-in: несколько стримов могут зарегистрировать одно имя и пушить в одну очередь.
// Очередь закрывается только когда последний вызвавший вызывает DetachWriter.
func AttachWriter(name string, bufferSize int) (queue.Queue, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if q, exists := ncsQueues[name]; exists {
		ncsRefs[name]++
		return q, nil
	}
	q := queue.NewMemoryQueue(bufferSize)
	ncsQueues[name] = q
	ncsRefs[name] = 1
	return q, nil
}

// AttachWriterWithQueue регистрирует предварительно сконфигурированную Queue для указанного имени.
// Если имя уже зарегистрировано — существующая очередь переиспользуется (fan-in);
// переданный q игнорируется, счётчик ссылок инкрементируется.
func AttachWriterWithQueue(name string, q queue.Queue) error {
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if _, exists := ncsQueues[name]; exists {
		ncsRefs[name]++
		return nil
	}
	ncsQueues[name] = q
	ncsRefs[name] = 1
	return nil
}

// RegisterSinkFromConfig создаёт Queue для указанного имени по cfg
// (memory / bbolt / redis backend) и регистрирует её в Named Channel Switch.
//
// Вызывается из: main.go при старте, до запуска горутин стримов с sentinel-threat sink'ами.
// Должен отработать ДО AttachWriter/AttachWriterWithQueue для того же имени — побеждает
// первая регистрация, последующие вызовы делают fan-in (refcount++). Это позволяет
// предварительной регистрации bbolt/redis backend'ов сосуществовать с последующим
// вызовом AttachWriter из sink'а.
//
// cfg == nil → идентично AttachWriter(name, 0): дефолтная MemoryQueue.
//
// Для bbolt и redis возвращаемая ошибка пробрасывается вызывающему, чтобы pipeline
// падал на misconfiguration (например, неверный path, недоступный Redis).
// Для memory (и nil cfg) ошибка невозможна — функция всегда возвращает nil.
// Возврат ошибки существует ради bbolt/redis и будущих backend-типов.
func RegisterSinkFromConfig(name string, cfg *queue.QueueConfig) error {
	// Nil-конфиг → откат на legacy MemoryQueue-путь, чтобы существующее поведение
	// сохранилось без изменения кода в точке вызова.
	if cfg == nil {
		_, err := AttachWriter(name, 0)
		return err
	}
	switch cfg.Type {
	case queue.QueueTypeMemory, "":
		// Пустой type тоже резолвится в memory — тот же дефолт, что и nil cfg.
		_, err := AttachWriter(name, 0)
		return err
	case queue.QueueTypeBbolt:
		// pkg/logger.Nop is used here as an intermediate state — the real bridge
		// (internal/sys/utils.AsLogger()) is wired in cmd/arxsentinel by Flow 072
		// Task 1.2.7. Until then the queue silently swallows QUEUE-tag warnings,
		// which matches the pre-1.2.7 behaviour of pkg/executor (silent by default
		// except for explicit Log calls in factory code).
		q, err := queue.NewBboltQueue(cfg.Path, cfg.EffectiveBucket(), logger.Nop)
		if err != nil {
			return fmt.Errorf("channelswitch: bbolt queue for %q (path=%q): %w", name, cfg.Path, err)
		}
		return AttachWriterWithQueue(name, q)
	case queue.QueueTypeRedis:
		q, err := queue.NewRedisQueue(cfg.URL, cfg.EffectiveKey(name))
		if err != nil {
			return fmt.Errorf("channelswitch: redis queue for %q (url=%q): %w", name, cfg.URL, err)
		}
		return AttachWriterWithQueue(name, q)
	default:
		return fmt.Errorf("channelswitch: unknown queue type %q for %q (want memory|bbolt|redis)", cfg.Type, name)
	}
}

// AttachReader возвращает Queue для ранее зарегистрированного имени.
// Вызывающий использует Queue.Pop(ctx) для получения событий.
// Возвращает ошибку, если очередь с таким именем не зарегистрирована.
func AttachReader(name string) (queue.Queue, error) {
	ncsMu.RLock()
	defer ncsMu.RUnlock()
	q, exists := ncsQueues[name]
	if !exists {
		return nil, fmt.Errorf("channelswitch: source %q not found", name)
	}
	return q, nil
}

// DetachWriter декрементирует счётчик ссылок именованной очереди.
// Очередь закрывается и удаляется только когда последний зарегистрированный sink дерегистрируется.
func DetachWriter(name string) {
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if ncsRefs[name] > 1 {
		ncsRefs[name]--
		return
	}
	if q, exists := ncsQueues[name]; exists {
		q.Close()
		delete(ncsQueues, name)
		delete(ncsRefs, name)
	}
}

// Compile-time гарантия, что queue.Queue реализует plugin.EventSource.
var _ plugin.EventSource = (queue.Queue)(nil)
