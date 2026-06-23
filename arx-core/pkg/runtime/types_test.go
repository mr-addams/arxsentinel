// ========================== pkg/runtime — types_test.go =================================
//   Юнит-тесты КОНТРАКТА. Engine.Run ещё не существует (Phase 2), поэтому здесь
//   тестируем только:
//     - что интерфейсы удовлетворяются (compile-time check);
//     - что ProcessorState opaque roundtrip через factory.Build / Reload;
//     - что MetricsCallbacks nil-safe (вызов nil-callback не паникует).
//
//   Запрещено импортировать что-либо из arxsentinel/... — boundary invariant.

package runtime

import (
	"context"
	"testing"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ mockLineProcessor — compile-time interface check ++++++++++++++

// mockLineProcessor — тестовая реализация LineProcessor. Реализует Process
// через замыкание, чтобы тесты могли подменять логику без новых типов.
type mockLineProcessor struct {
	processFn func(ctx context.Context, ev *plugin.Event, state ProcessorState, evctx EventContext) Action
}

func (m *mockLineProcessor) Process(
	ctx context.Context,
	ev *plugin.Event,
	state ProcessorState,
	evctx EventContext,
) Action {
	if m.processFn == nil {
		// дефолтная no-op реализация для compile-time гарантии интерфейса.
		return Action{}
	}
	return m.processFn(ctx, ev, state, evctx)
}

// Compile-time гарантия: mockLineProcessor удовлетворяет LineProcessor.
// Если сигнатура Process изменится, тест НЕ СКОМПИЛИРУЕТСЯ — это и есть проверка.
var _ LineProcessor = (*mockLineProcessor)(nil)

// ++++++++++++++++++++++++++ Test: LineProcessor interface satisfaction +++++++++++++++++++

// TestLineProcessorInterfaceAcceptsMock проверяет compile-time удовлетворение
// интерфейса и базовый roundtrip: вызываем Process, получаем ожидаемый Action.
func TestLineProcessorInterfaceAcceptsMock(t *testing.T) {
	t.Parallel()

	var capturedEvctx EventContext
	var capturedState ProcessorState

	proc := &mockLineProcessor{
		processFn: func(
			_ context.Context,
			_ *plugin.Event,
			state ProcessorState,
			evctx EventContext,
		) Action {
			capturedState = state
			capturedEvctx = evctx
			return Action{}
		},
	}

	// Opаковое значение state, которое Product обычно возвращает из factory.Build.
	// Используем структуру, чтобы можно было сравнить через ==.
	state := &stateWithVersion{Version: 7, Tag: "initial"}
	evctx := EventContext{
		StreamName:   "edge",
		PipelineName: "main",
		SourceName:   "file:/var/log/access.log",
		SourceType:   "file",
		PipelineIdx:  0,
	}
	entry := &parser.LogEntry{RemoteAddr: "1.2.3.4"}
	event := parser.WrapLogEntry(entry, plugin.Envelope{
		Source:     "1.2.3.4",
		SourceType: "file",
		Timestamp:  entry.Time,
	})

	action := proc.Process(context.Background(), event, state, evctx)

	if action.Skip {
		t.Fatalf("expected Skip=false, got Skip=true")
	}
	if action.Payload != nil {
		t.Fatalf("expected Payload=nil, got %+v", action.Payload)
	}
	if capturedState != state {
		t.Fatalf("Process did not receive the same state reference")
	}
	if capturedEvctx != evctx {
		t.Fatalf("Process did not receive the expected EventContext: got %+v, want %+v",
			capturedEvctx, evctx)
	}
}

// ++++++++++++++++++++++++++ mockLineProcessorFactory ++++++++++++++++++++++++++++++++++++

// mockLineProcessorFactory — тестовая реализация LineProcessorFactory.
// Build возвращает начальный state, Reload возвращает state-bump'нутый счётчик.
type mockLineProcessorFactory struct {
	buildFn  func(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error)
	reloadFn func(old ProcessorState, ctx context.Context) (ProcessorState, error)
}

func (m *mockLineProcessorFactory) Build(
	streamName, pipeName string, pipeIdx int, shared SharedResources,
) (ProcessorState, error) {
	if m.buildFn == nil {
		return nil, nil
	}
	return m.buildFn(streamName, pipeName, pipeIdx, shared)
}

func (m *mockLineProcessorFactory) Reload(
	old ProcessorState, ctx context.Context,
) (ProcessorState, error) {
	if m.reloadFn == nil {
		return old, nil
	}
	return m.reloadFn(old, ctx)
}

// Compile-time гарантия: factory удовлетворяет интерфейсу.
var _ LineProcessorFactory = (*mockLineProcessorFactory)(nil)

// ++++++++++++++++++++++++++ Test: ProcessorState roundtrip через Build/Reload ++++++++++++

// stateWithVersion — opaque-значение, которое Product мог бы вернуть из Build.
// Используем struct вместо map, чтобы подчеркнуть что state — opaque.
type stateWithVersion struct {
	Version int
	Tag     string
}

// TestProcessorStateRoundtrip проверяет что:
//  1. factory.Build возвращает opaque state;
//  2. factory.Reload возвращает НОВЫЙ state (не мутирует старый);
//  3. Product может сохранить любое значение как ProcessorState.
func TestProcessorStateRoundtrip(t *testing.T) {
	t.Parallel()

	factory := &mockLineProcessorFactory{
		buildFn: func(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error) {
			return &stateWithVersion{Version: 1, Tag: streamName + "/" + pipeName}, nil
		},
		reloadFn: func(old ProcessorState, ctx context.Context) (ProcessorState, error) {
			prev, ok := old.(*stateWithVersion)
			if !ok {
				t.Fatalf("expected *stateWithVersion in Reload, got %T", old)
			}
			return &stateWithVersion{Version: prev.Version + 1, Tag: prev.Tag}, nil
		},
	}

	shared := SharedResources{} // пустой opaque-контейнер — Core не трогает поля.

	initial, err := factory.Build("edge", "main", 0, shared)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	initialState, ok := initial.(*stateWithVersion)
	if !ok {
		t.Fatalf("Build did not return *stateWithVersion, got %T", initial)
	}
	if initialState.Version != 1 || initialState.Tag != "edge/main" {
		t.Fatalf("unexpected initial state: %+v", initialState)
	}

	reloaded, err := factory.Reload(initial, context.Background())
	if err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}
	reloadedState, ok := reloaded.(*stateWithVersion)
	if !ok {
		t.Fatalf("Reload did not return *stateWithVersion, got %T", reloaded)
	}

	// Reload должен вернуть НОВЫЙ state (не тот же указатель) с инкрементом.
	if reloadedState == initialState {
		t.Fatalf("Reload returned the same pointer; expected new state")
	}
	if reloadedState.Version != 2 {
		t.Fatalf("expected Version=2 after reload, got %d", reloadedState.Version)
	}
	if reloadedState.Tag != "edge/main" {
		t.Fatalf("expected Tag preserved across reload, got %q", reloadedState.Tag)
	}

	// Старый state не должен мутировать.
	if initialState.Version != 1 {
		t.Fatalf("initial state mutated by Reload: Version=%d (want 1)", initialState.Version)
	}
}

// ++++++++++++++++++++++++++ Test: nil-safety MetricsCallbacks +++++++++++++++++++++++++++++

// TestMetricsCallbacksNilSafe проверяет контракт nil-safety: если Product
// не зарегистрировал callback, Core-runtime ОБЯЗАН проверять `cb != nil`
// перед вызовом. Здесь мы напрямую проверяем что:
//  1. nil-структура MetricsCallbacks{} — все поля nil;
//  2. попытка вызвать любой callback как метод на nil-структуре НЕ проверяется
//     контрактом — это ответственность call-site (Core-runtime).
//  3. Если call-site проверяет `if cb != nil && cb.Field != nil`, то вызов
//     пустой структуры ничего не делает и не паникует.
//
// Этот тест документирует контракт: сам факт, что все поля — func-типы
// с zero-value = nil — это и есть nil-safety гарантия для call-site.
func TestMetricsCallbacksNilSafe(t *testing.T) {
	t.Parallel()

	// 1. Дефолтное zero-value MetricsCallbacks: все поля nil.
	var cb *MetricsCallbacks = nil
	if cb != nil {
		t.Fatalf("expected nil pointer, got non-nil")
	}

	// 2. Не-nil структура, но все поля nil.
	cb = &MetricsCallbacks{}
	if cb.RecordLine != nil {
		t.Fatalf("RecordLine must be nil for zero-value MetricsCallbacks")
	}
	if cb.RecordThreat != nil {
		t.Fatalf("RecordThreat must be nil for zero-value MetricsCallbacks")
	}
	if cb.RecordInputLine != nil {
		t.Fatalf("RecordInputLine must be nil for zero-value MetricsCallbacks")
	}
	if cb.RecordDetectorHit != nil {
		t.Fatalf("RecordDetectorHit must be nil for zero-value MetricsCallbacks")
	}
	if cb.RecordOutputEvent != nil {
		t.Fatalf("RecordOutputEvent must be nil for zero-value MetricsCallbacks")
	}
	if cb.UpdateGauges != nil {
		t.Fatalf("UpdateGauges must be nil for zero-value MetricsCallbacks")
	}

	// 3. Имитируем Core-runtime: call-site проверяет nil перед вызовом.
	//    Это и есть документированный контракт — здесь мы фиксируем что
	//    такой паттерн НЕ паникует.
	calls := 0
	// RecordLine: 4 string параметра.
	if cb != nil && cb.RecordLine != nil {
		cb.RecordLine("edge", "main", "file:/x", "file")
		calls++
	}
	// RecordThreat: 3 string параметра (нет sourceName/sourceType).
	if cb != nil && cb.RecordThreat != nil {
		cb.RecordThreat("edge", "main", "WARN")
		calls++
	}
	if calls != 0 {
		t.Fatalf("expected 0 calls (all callbacks nil), got %d", calls)
	}

	// 4. После установки одного callback'а — он должен вызваться.
	callsToRecordLine := 0
	cb.RecordLine = func(_, _, _, _ string) {
		callsToRecordLine++
	}
	if cb != nil && cb.RecordLine != nil {
		cb.RecordLine("edge", "main", "file:/x", "file")
	}
	if callsToRecordLine != 1 {
		t.Fatalf("expected RecordLine to be invoked once, got %d", callsToRecordLine)
	}

	// 5. Другой callback остался nil — call-site пропускает.
	if cb != nil && cb.RecordThreat != nil {
		cb.RecordThreat("edge", "main", "WARN")
	}
	if callsToRecordLine != 1 {
		t.Fatalf("RecordThreat (nil) must not affect RecordLine counter; got %d", callsToRecordLine)
	}
}

// ++++++++++++++++++++++++++ Test: LogFn как независимый тип ++++++++++++++++++++++++++++++

// TestLogFnIsNamedType проверяет что LogFn — это именованный тип
// (а не type alias на внешний пакет), что позволяет runtime быть самодостаточным.
func TestLogFnIsNamedType(t *testing.T) {
	t.Parallel()

	var fn LogFn = func(tag, msg, level string) {
		// no-op для compile-time проверки сигнатуры.
		_ = tag
		_ = msg
		_ = level
	}
	if fn == nil {
		t.Fatalf("LogFn must be assignable from a func literal")
	}
}
