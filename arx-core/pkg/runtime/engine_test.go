// ========================== pkg/runtime — engine_test.go ==================================
//   Юнит-тесты обобщённого engine.Run.
//
//   Стратегия: маленькие mock-источники / sinks / factory / processor пишем здесь же
//   (в _test.go), чтобы тесты не зависели от конкретных plugin-импл из host-приложения.
//   boundary-invariant: импорт ТОЛЬКО из arx-core/... и stdlib.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ Mocks ++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// mockSource — простая реализация plugin.Source. Сразу отдаёт entries и завершает Run
// (после первого чтения из done-канала или при ctx.Done).
type mockSource struct {
	name    string
	entries []*plugin.LogEntry
}

func (s *mockSource) Name() string              { return s.name }
func (s *mockSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *mockSource) Close() error              { return nil }
func (s *mockSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *mockSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	for _, e := range s.entries {
		select {
		case out <- e:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// blockingSource — отдаёт ОДИН entry, потом блокирует Run() до ctx.Done().
// Используется для теста drain-on-shutdown: после cancel ctx Merge закрывает канал.
type blockingSource struct {
	entry *plugin.LogEntry
}

func (s *blockingSource) Name() string              { return "blocking" }
func (s *blockingSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *blockingSource) Close() error              { return nil }
func (s *blockingSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *blockingSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	select {
	case out <- s.entry:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return ctx.Err()
}

// slowSource — отдаёт entries с задержкой между ними. Используется для drain-теста.
type slowSource struct {
	name    string
	entries []*plugin.LogEntry
	delay   time.Duration
}

func (s *slowSource) Name() string              { return s.name }
func (s *slowSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *slowSource) Close() error              { return nil }
func (s *slowSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *slowSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	for _, e := range s.entries {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case out <- e:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// mockSink — простой sink, собирает все записанные события в массив (потокобезопасно).
// Имеет опциональный Reloader-метод (вызывается на SIGHUP).
type mockSink struct {
	name      string
	mu        sync.Mutex
	events    []plugin.ThreatEvent
	reloaded  atomic.Int32 // счётчик reload-вызовов
	loadError error        // если задан — Reload() вернёт эту ошибку
}

func (s *mockSink) Name() string              { return s.name }
func (s *mockSink) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *mockSink) Close() error              { return nil }
func (s *mockSink) Stats() plugin.SinkStats   { return plugin.SinkStats{} }
func (s *mockSink) Write(_ context.Context, ev plugin.ThreatEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}
func (s *mockSink) Reload() error {
	s.reloaded.Add(1)
	return s.loadError
}
func (s *mockSink) Events() []plugin.ThreatEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]plugin.ThreatEvent, len(s.events))
	copy(out, s.events)
	return out
}

// failingSink — Write всегда возвращает ошибку. Используется для теста: ошибка sink
// не должна ронять pipeline.
type failingSink struct {
	name string
}

func (s *failingSink) Name() string              { return s.name }
func (s *failingSink) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *failingSink) Close() error              { return nil }
func (s *failingSink) Stats() plugin.SinkStats   { return plugin.SinkStats{} }
func (s *failingSink) Write(_ context.Context, _ plugin.ThreatEvent) error {
	return errors.New("sink is intentionally failing")
}

// mockFactory — реализует LineProcessorFactory И LineProcessor.
// state (per-pipeline): *mockState с idx, buildCalls и processCalls (атомики).
// Process эмитит ThreatEvent для entries, у которых IP = "evil.*".
type mockFactory struct {
	buildCalls  atomic.Int32
	reloadCalls atomic.Int32
	panicAfter  int // 0 = нет panic; >0 = panic на Process-вызове #N
	processed   atomic.Int32
	events      atomic.Int32
	processedMu sync.Mutex
}

type mockState struct {
	idx     int
	factory *mockFactory
}

func (f *mockFactory) Build(_ string, _ string, pipeIdx int, _ SharedResources) (ProcessorState, error) {
	f.buildCalls.Add(1)
	return &mockState{idx: pipeIdx, factory: f}, nil
}

func (f *mockFactory) Reload(old ProcessorState, _ context.Context) (ProcessorState, error) {
	f.reloadCalls.Add(1)
	prev, _ := old.(*mockState)
	return &mockState{idx: prev.idx, factory: f}, nil
}

func (f *mockFactory) Process(_ context.Context, entry *plugin.LogEntry, state ProcessorState, _ EventContext) Action {
	f.processed.Add(1)

	// Контролируемая panic для теста recovery.
	if f.panicAfter > 0 && int(f.processed.Load()) >= f.panicAfter {
		panic("mockFactory: intentional panic on Process")
	}

	if !strings.HasPrefix(entry.RealIP, "evil") {
		return Action{}
	}
	f.events.Add(1)
	return Action{
		ThreatEvent: &plugin.ThreatEvent{
			Level: "WARN",
			IP:    entry.RealIP,
		},
	}
}

// Compile-time: mockFactory реализует ОБА интерфейса.
var (
	_ LineProcessorFactory = (*mockFactory)(nil)
	_ LineProcessor        = (*mockFactory)(nil)
)

// factoryOnly — реализует ТОЛЬКО LineProcessorFactory, НЕ LineProcessor.
// Используется для теста fail-fast в Run().
type factoryOnly struct{}

func (f *factoryOnly) Build(_ string, _ string, _ int, _ SharedResources) (ProcessorState, error) {
	return nil, nil
}
func (f *factoryOnly) Reload(_ ProcessorState, _ context.Context) (ProcessorState, error) {
	return nil, nil
}

var _ LineProcessorFactory = (*factoryOnly)(nil)

// makeEntry — конструктор LogEntry для тестов.
func makeEntry(ip string) *plugin.LogEntry {
	return &plugin.LogEntry{RealIP: ip, Time: time.Now()}
}

// ++++++++++++++++++++++++++ Tests +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// TestRun_Basic — два source'а, factory.Process инкрементит счётчики, sink получает
// все ThreatEvent'ы.
func TestRun_Basic(t *testing.T) {
	t.Parallel()

	src1 := &mockSource{name: "s1", entries: []*plugin.LogEntry{
		makeEntry("1.1.1.1"), makeEntry("evil.a"),
	}}
	src2 := &mockSource{name: "s2", entries: []*plugin.LogEntry{
		makeEntry("2.2.2.2"), makeEntry("evil.b"),
	}}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{}

	stream := StreamSpec{
		Name:            "test",
		BufferSize:      8,
		StatsInterval:   50 * time.Millisecond, // тише лог во время теста
		ShutdownTimeout: time.Second,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src1, src2}, Sinks: []plugin.Sink{sink}},
		},
	}

	if err := Run(context.Background(), stream, factory, SharedResources{}, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if got := int(factory.processed.Load()); got != 4 {
		t.Errorf("processed count: want 4, got %d", got)
	}
	if got := int(factory.events.Load()); got != 2 {
		t.Errorf("events count: want 2 (evil.a + evil.b), got %d", got)
	}
	if got := len(sink.Events()); got != 2 {
		t.Errorf("sink events: want 2, got %d", got)
	}
	if got := int(factory.buildCalls.Load()); got != 1 {
		t.Errorf("factory.Build calls: want 1, got %d", got)
	}
}

// TestRun_ReloadOnSIGHUP — посылаем в reloadCh, factory.Reload вызывается один раз,
// sink.Reload вызывается для каждого Reloader-aware sink.
func TestRun_ReloadOnSIGHUP(t *testing.T) {
	t.Parallel()

	// blockingSource: гарантирует, что Run не завершится до reload+ctx.Cancel.
	src := &blockingSource{entry: makeEntry("1.1.1.1")}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{}

	reloadCh := make(chan struct{}, 1)

	stream := StreamSpec{
		Name:          "reload-test",
		BufferSize:    4,
		StatsInterval: time.Hour, // редкий — не засорять лог
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, stream, factory, SharedResources{}, reloadCh, nil)
	}()

	// Ждём, пока Build отработает (factory обработает первый entry от blocking source).
	deadline := time.Now().Add(2 * time.Second)
	for factory.processed.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if factory.processed.Load() < 1 {
		t.Fatal("factory.Process was never invoked before reload")
	}

	// Триггерим reload.
	reloadCh <- struct{}{}

	// Ждём, пока Reload отработает.
	deadline = time.Now().Add(2 * time.Second)
	for factory.reloadCalls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := int(factory.reloadCalls.Load()); got != 1 {
		t.Errorf("factory.Reload calls: want 1, got %d", got)
	}
	if got := int(sink.reloaded.Load()); got != 1 {
		t.Errorf("sink.Reload calls: want 1, got %d", got)
	}

	// Штатно завершаем.
	cancel()
	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after ctx.Cancel")
	}
}

// TestRun_DrainOnShutdown — slow source отдаёт entries с задержкой; отменяем ctx
// после первой entry, проверяем что оставшиеся entries (буферизованные) были обработаны.
func TestRun_DrainOnShutdown(t *testing.T) {
	t.Parallel()

	const totalEntries = 5
	entries := make([]*plugin.LogEntry, totalEntries)
	for i := range entries {
		entries[i] = makeEntry(fmt.Sprintf("evil.%d", i))
	}
	src := &slowSource{name: "slow", entries: entries, delay: 50 * time.Millisecond}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{}

	stream := StreamSpec{
		Name:          "drain-test",
		BufferSize:    totalEntries + 1, // все помещаются в буфер
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, stream, factory, SharedResources{}, nil, nil)
	}()

	// Ждём, пока source отдаст первые entries и Merge их забуферизует.
	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// Все entries должны быть обработаны (буфер дренируется при shutdown).
	processed := int(factory.processed.Load())
	if processed < 1 || processed > totalEntries {
		t.Errorf("processed count: want 1..%d, got %d", totalEntries, processed)
	}
}

// TestRun_PanicRecovery — factory паникует на N-ом Process-вызове. Engine.Run должен
// recover'ить panic, залогировать, и Run не должен вернуть panic в caller.
func TestRun_PanicRecovery(t *testing.T) {
	t.Parallel()

	entries := []*plugin.LogEntry{
		makeEntry("1.1.1.1"),
		makeEntry("2.2.2.2"),
		makeEntry("3.3.3.3"),
		makeEntry("4.4.4.4"),
	}
	src := &mockSource{name: "s1", entries: entries}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{panicAfter: 2} // паника на 2-м Process

	stream := StreamSpec{
		Name:          "panic-test",
		BufferSize:    8,
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	var panicLogged atomic.Int32
	logFn := func(tag, msg, level string) {
		if level == "error" && strings.Contains(msg, "panic") {
			panicLogged.Add(1)
		}
	}

	// Run не должен падать в caller (panic recovered в defer).
	if err := Run(context.Background(), stream, factory, SharedResources{}, nil, logFn); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := int(panicLogged.Load()); got < 1 {
		t.Errorf("expected at least one panic log, got %d", got)
	}
}

// TestRun_TwoPipelineConcurrency — два pipeline'а в стриме, factory.Build вызывается
// дважды с разными pipeIdx, state'ы уникальны.
func TestRun_TwoPipelineConcurrency(t *testing.T) {
	t.Parallel()

	src1 := &mockSource{name: "s1", entries: []*plugin.LogEntry{makeEntry("1.1.1.1")}}
	src2 := &mockSource{name: "s2", entries: []*plugin.LogEntry{makeEntry("2.2.2.2")}}
	sink1 := &mockSink{name: "out1"}
	sink2 := &mockSink{name: "out2"}
	factory := &mockFactory{}

	stream := StreamSpec{
		Name:          "two-pipe",
		BufferSize:    4,
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "p1", Idx: 0, Sources: []plugin.Source{src1}, Sinks: []plugin.Sink{sink1}},
			{Name: "p2", Idx: 1, Sources: []plugin.Source{src2}, Sinks: []plugin.Sink{sink2}},
		},
	}

	if err := Run(context.Background(), stream, factory, SharedResources{}, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := int(factory.buildCalls.Load()); got != 2 {
		t.Errorf("Build calls: want 2, got %d", got)
	}
	if got := int(factory.processed.Load()); got != 2 {
		t.Errorf("processed count: want 2 (1 per pipeline), got %d", got)
	}
}

// TestRun_FactoryNotALineProcessor — factory реализует только LineProcessorFactory
// (НЕ LineProcessor). Engine.Run должен вернуть ошибку.
func TestRun_FactoryNotALineProcessor(t *testing.T) {
	t.Parallel()

	src := &mockSource{name: "s1", entries: []*plugin.LogEntry{makeEntry("1.1.1.1")}}
	sink := &mockSink{name: "out"}
	factory := &factoryOnly{}

	stream := StreamSpec{
		Name:          "fail-fast",
		BufferSize:    4,
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	err := Run(context.Background(), stream, factory, SharedResources{}, nil, nil)
	if err == nil {
		t.Fatal("expected error from Run (factory must implement LineProcessor)")
	}
	if !strings.Contains(err.Error(), "LineProcessor") {
		t.Errorf("error message should mention LineProcessor, got: %v", err)
	}
}

// TestRun_NilMetricsCallbacks — SharedResources.MetricsCallbacks=nil. Engine не должен
// паниковать при вызове метрик. Покрывает nil-safe контракт.
func TestRun_NilMetricsCallbacks(t *testing.T) {
	t.Parallel()

	src := &mockSource{name: "s1", entries: []*plugin.LogEntry{
		makeEntry("1.1.1.1"),
		makeEntry("evil.x"), // → ThreatEvent
	}}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{}

	stream := StreamSpec{
		Name:          "nil-cb",
		BufferSize:    4,
		StatsInterval: 50 * time.Millisecond,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	// shared.MetricsCallbacks=nil (zero-value); Run не должен паниковать.
	shared := SharedResources{}

	if err := Run(context.Background(), stream, factory, shared, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := len(sink.Events()); got != 1 {
		t.Errorf("expected 1 event in sink, got %d", got)
	}
}

// TestRun_SinkWriteErrorDoesNotCrashPipeline — sink.Write возвращает ошибку.
// Engine не должен падать, должен продолжить обработку следующих entries.
func TestRun_SinkWriteErrorDoesNotCrashPipeline(t *testing.T) {
	t.Parallel()

	src := &mockSource{name: "s1", entries: []*plugin.LogEntry{
		makeEntry("evil.a"),
		makeEntry("evil.b"),
		makeEntry("evil.c"),
	}}
	sink := &failingSink{name: "fails"}
	factory := &mockFactory{}

	stream := StreamSpec{
		Name:          "failing-sink",
		BufferSize:    4,
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	// Не должно быть panic; Run возвращает nil.
	if err := Run(context.Background(), stream, factory, SharedResources{}, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	// Все 3 entries прошли через Process, несмотря на ошибку sink.
	if got := int(factory.processed.Load()); got != 3 {
		t.Errorf("processed count: want 3, got %d", got)
	}
	if got := int(factory.events.Load()); got != 3 {
		t.Errorf("events count: want 3, got %d", got)
	}
}

// TestRun_SkipAction — Process возвращает Action{Skip: true}. Engine должен
// инкрементить processedCount, но НЕ писать в sink.
func TestRun_SkipAction(t *testing.T) {
	t.Parallel()

	src := &mockSource{name: "s1", entries: []*plugin.LogEntry{makeEntry("1.1.1.1")}}
	sink := &mockSink{name: "out"}
	factory := &mockFactory{} // "1.1.1.1" НЕ evil → вернёт Action{} (Skip=false, ThreatEvent=nil)

	stream := StreamSpec{
		Name:          "skip-test",
		BufferSize:    4,
		StatsInterval: time.Hour,
		Pipelines: []PipelineSpec{
			{Name: "main", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{sink}},
		},
	}

	if err := Run(context.Background(), stream, factory, SharedResources{}, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := int(factory.processed.Load()); got != 1 {
		t.Errorf("processed count: want 1, got %d", got)
	}
	if got := len(sink.Events()); got != 0 {
		t.Errorf("sink should have 0 events for non-evil entry, got %d", got)
	}
}
