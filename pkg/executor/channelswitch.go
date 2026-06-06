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
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// DefaultBufferSize используется при вызове AttachWriter с bufferSize <= 0.
const DefaultBufferSize = 1000

var (
	hubMu     sync.RWMutex
	hubQueues = map[string]queue.Queue{}
	// hubRefs считает, сколько sink'ов разделяют одну именованную очередь.
	// DetachWriter закрывает очередь только когда последний sink дерегистрируется.
	hubRefs = map[string]int{}
)

// AttachWriter возвращает MemoryQueue для указанного имени, создавая её при необходимости.
// Fan-in: несколько стримов могут зарегистрировать одно имя и пушить в одну очередь.
// Очередь закрывается только когда последний вызвавший вызывает DetachWriter.
func AttachWriter(name string, bufferSize int) (queue.Queue, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if q, exists := hubQueues[name]; exists {
		hubRefs[name]++
		return q, nil
	}
	q := queue.NewMemoryQueue(bufferSize)
	hubQueues[name] = q
	hubRefs[name] = 1
	return q, nil
}

// AttachWriterWithQueue регистрирует предварительно сконфигурированную Queue для указанного имени.
// Если имя уже зарегистрировано — существующая очередь переиспользуется (fan-in);
// переданный q игнорируется, счётчик ссылок инкрементируется.
func AttachWriterWithQueue(name string, q queue.Queue) error {
	hubMu.Lock()
	defer hubMu.Unlock()
	if _, exists := hubQueues[name]; exists {
		hubRefs[name]++
		return nil
	}
	hubQueues[name] = q
	hubRefs[name] = 1
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
		q, err := queue.NewBboltQueue(cfg.Path, cfg.EffectiveBucket())
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
	hubMu.RLock()
	defer hubMu.RUnlock()
	q, exists := hubQueues[name]
	if !exists {
		return nil, fmt.Errorf("channelswitch: source %q not found", name)
	}
	return q, nil
}

// DetachWriter декрементирует счётчик ссылок именованной очереди.
// Очередь закрывается и удаляется только когда последний зарегистрированный sink дерегистрируется.
func DetachWriter(name string) {
	hubMu.Lock()
	defer hubMu.Unlock()
	if hubRefs[name] > 1 {
		hubRefs[name]--
		return
	}
	if q, exists := hubQueues[name]; exists {
		q.Close()
		delete(hubQueues, name)
		delete(hubRefs, name)
	}
}

// Compile-time гарантия, что queue.Queue реализует plugin.EventSource.
var _ plugin.EventSource = (queue.Queue)(nil)
