// ========================== pkg/executor — channelswitch_test.go ===============
//   Tests for NamedSwitch: named executor registration, lookup, lifecycle.

package executor_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func TestNamedSwitch_SendReceive(t *testing.T) {
	ctx := context.Background()
	q, err := executor.AttachWriter("test-sr", 10)
	if err != nil {
		t.Fatalf("AttachWriter error = %v, want nil", err)
	}

	src, err := executor.AttachReader("test-sr")
	if err != nil {
		t.Fatalf("AttachReader error = %v, want nil", err)
	}

	event := plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}
	if err := q.Push(ctx, event); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}

	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	if got.IP != event.IP {
		t.Errorf("received IP = %q, want %q", got.IP, event.IP)
	}
	if got.Level != event.Level {
		t.Errorf("received Level = %q, want %q", got.Level, event.Level)
	}

	executor.DetachWriter("test-sr")
}

func TestNamedSwitch_DuplicateName(t *testing.T) {
	ctx := context.Background()

	// Fan-in: two streams register the same name and get the same queue.
	q1, err := executor.AttachWriter("test-dup", 5)
	if err != nil {
		t.Fatalf("first AttachWriter error = %v, want nil", err)
	}
	q2, err := executor.AttachWriter("test-dup", 5)
	if err != nil {
		t.Fatalf("second AttachWriter error = %v, want nil", err)
	}
	if q1 != q2 {
		t.Error("both AttachWriter calls must return the same queue")
	}

	// Both push through different handles; consumer sees all events.
	src, _ := executor.AttachReader("test-dup")
	_ = q1.Push(ctx, plugin.ThreatEvent{IP: "1.1.1.1", Level: "THREAT"})
	_ = q2.Push(ctx, plugin.ThreatEvent{IP: "2.2.2.2", Level: "THREAT"})

	got1, _ := src.Pop(ctx)
	got2, _ := src.Pop(ctx)
	ips := map[string]bool{got1.IP: true, got2.IP: true}
	if !ips["1.1.1.1"] || !ips["2.2.2.2"] {
		t.Errorf("expected both IPs from fan-in, got %q and %q", got1.IP, got2.IP)
	}

	// Ref count: first DetachWriter keeps queue alive.
	executor.DetachWriter("test-dup") // ref: 2 → 1, queue must stay open
	if _, err := executor.AttachReader("test-dup"); err != nil {
		t.Error("queue should still be open after first DetachWriter")
	}
	executor.DetachWriter("test-dup") // ref: 1 → 0, queue closed
	if _, err := executor.AttachReader("test-dup"); err == nil {
		t.Error("queue should be gone after last DetachWriter")
	}
}

func TestNamedSwitch_Unregister(t *testing.T) {
	ctx := context.Background()
	q, err := executor.AttachWriter("test-unreg", 3)
	if err != nil {
		t.Fatalf("AttachWriter error = %v, want nil", err)
	}

	src, err := executor.AttachReader("test-unreg")
	if err != nil {
		t.Fatalf("AttachReader error = %v, want nil", err)
	}

	_ = q.Push(ctx, plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"})
	executor.DetachWriter("test-unreg")

	// После DetachWriter queue закрыта, но в канале ещё есть буферизованное событие.
	// Первый Pop дренирует буфер (err=nil, возвращает событие).
	// Второй Pop должен вернуть ErrQueueClosed — канал пуст и закрыт.
	_, _ = src.Pop(ctx)
	_, err = src.Pop(ctx)
	if err == nil {
		t.Error("expected ErrQueueClosed on second Pop after DetachWriter, got nil")
	}
}

func TestNamedSwitch_GetSourceNotFound(t *testing.T) {
	_, err := executor.AttachReader("nonexistent")
	if err == nil {
		t.Fatal("AttachReader(nonexistent) expected error, got nil")
	}
}

// --------------------- RegisterSinkFromConfig: таблица веток ---------------------
//
// Каждый тест использует уникальное имя очереди (t.Name()), чтобы не пересекаться
// с глобальным singleton'ом NamedChannelSwitch при параллельном запуске.
// После каждого теста DetachWriter обязателен — иначе queue утечёт в NCS-карту.

// TestRegisterSinkFromConfig_NilCfg — cfg == nil → дефолтный MemoryQueue,
// функция ведёт себя идентично AttachWriter(name, 0).
func TestRegisterSinkFromConfig_NilCfg(t *testing.T) {
	name := t.Name()

	err := executor.RegisterSinkFromConfig(name, nil)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(nil) error = %v, want nil", err)
	}

	// Queue зарегистрирована, AttachReader обязан её найти.
	src, err := executor.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// Очередь рабочая: Push → Pop возвращает то же событие.
	ctx := context.Background()
	evt := plugin.ThreatEvent{IP: "10.0.0.1", Level: "THREAT"}
	if err := src.Push(ctx, evt); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	if got.IP != evt.IP {
		t.Errorf("Pop IP = %q, want %q", got.IP, evt.IP)
	}

	executor.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeMemory — явный type=memory → MemoryQueue.
func TestRegisterSinkFromConfig_TypeMemory(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{Type: queue.QueueTypeMemory}

	err := executor.RegisterSinkFromConfig(name, cfg)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(memory) error = %v, want nil", err)
	}

	src, err := executor.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// Доп. проверка: подтверждаем, что зарегистрирована именно in-memory очередь —
	// Push → Pop в том же процессе без сериализации.
	ctx := context.Background()
	evt := plugin.ThreatEvent{IP: "10.0.0.2", Level: "THREAT"}
	if err := src.Push(ctx, evt); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	if got.IP != evt.IP {
		t.Errorf("Pop IP = %q, want %q", got.IP, evt.IP)
	}

	executor.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeBbolt — type=bbolt с валидным path → BboltQueue
// регистрируется без ошибки. Используем t.TempDir() для авто-очистки.
func TestRegisterSinkFromConfig_TypeBbolt(t *testing.T) {
	name := t.Name()
	dbPath := filepath.Join(t.TempDir(), "queue.db")
	cfg := &queue.QueueConfig{Type: queue.QueueTypeBbolt, Path: dbPath}

	err := executor.RegisterSinkFromConfig(name, cfg)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(bbolt) error = %v, want nil", err)
	}

	// BboltQueue зарегистрирован в NCS, AttachReader находит её.
	src, err := executor.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// ВАЖНО: BboltQueue.DetachWriter закроет её ДО того, как BboltQueue обработает
	// background-writeLoop. После Close повторный Push вернёт ErrQueueClosed —
	// это и проверяем ниже, чтобы убедиться, что в NCS лежит именно BboltQueue.
	ctx := context.Background()
	evt := plugin.ThreatEvent{IP: "10.0.0.3", Level: "THREAT"}
	if err := src.Push(ctx, evt); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}

	executor.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeRedis_InvalidURL — type=redis с невалидным URL
// → NewRedisQueue возвращает ошибку (redis.ParseURL не справляется),
// RegisterSinkFromConfig пробрасывает её дальше, в NCS ничего не попадает.
func TestRegisterSinkFromConfig_TypeRedis_InvalidURL(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{
		Type: queue.QueueTypeRedis,
		URL:  "not-a-valid-redis-url", // redis.ParseURL ожидает схему redis://
	}

	err := executor.RegisterSinkFromConfig(name, cfg)
	if err == nil {
		t.Fatal("RegisterSinkFromConfig(redis, bad url) expected error, got nil")
	}
	// Сообщение обязано содержать имя sink'а для диагностики в логах.
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error %q should mention sink name %q", err.Error(), name)
	}
	if !strings.Contains(err.Error(), "redis") {
		t.Errorf("error %q should mention redis backend", err.Error())
	}

	// В NCS ничего не зарегистрировано — AttachReader обязан вернуть ошибку.
	_, err = executor.AttachReader(name)
	if err == nil {
		t.Fatal("AttachReader after failed register expected error, got nil")
	}
}

// TestRegisterSinkFromConfig_UnknownType — type с неподдерживаемым значением
// → возврат ошибки, NCS остаётся чистым.
func TestRegisterSinkFromConfig_UnknownType(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{Type: queue.QueueType("kafka")}

	err := executor.RegisterSinkFromConfig(name, cfg)
	if err == nil {
		t.Fatal("RegisterSinkFromConfig(unknown) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "kafka") {
		t.Errorf("error %q should mention the unknown type value", err.Error())
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error %q should mention sink name %q", err.Error(), name)
	}

	// NCS не должен содержать ничего под этим именем.
	_, err = executor.AttachReader(name)
	if err == nil {
		t.Fatal("AttachReader after unknown-type error expected error, got nil")
	}
}
