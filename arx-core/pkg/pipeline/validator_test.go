// ========================== pkg/pipeline — Pipeline validator tests =========================

package pipeline

import (
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		chain []plugin.Manifest
		want  int
	}{
		{
			name: "valid full pipeline",
			chain: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				{PluginID: "chaincheck", InputType: plugin.TypeStructured, OutputType: plugin.TypeStructured},
				{PluginID: "probe", InputType: plugin.TypeStructured, OutputType: plugin.TypeScoredEvent},
				{PluginID: "file-sink", InputType: plugin.TypeScoredEvent, OutputType: plugin.TypeNone},
			},
			want: 0,
		},
		{
			name: "valid ETL",
			chain: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				{PluginID: "file-sink", InputType: plugin.TypeStructured, OutputType: plugin.TypeNone},
			},
			want: 0,
		},
		{
			name: "TypeAny bridge",
			chain: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeAny},
				{PluginID: "file-sink", InputType: plugin.TypeScoredEvent, OutputType: plugin.TypeNone},
			},
			want: 0,
		},
		{
			name: "incompatible types",
			chain: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				{PluginID: "file-sink", InputType: plugin.TypeScoredEvent, OutputType: plugin.TypeNone},
			},
			want: 1,
		},
		{
			name:  "empty chain",
			chain: nil,
			want:  0,
		},
		{
			name: "single plugin",
			chain: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Validate(tt.chain)
			if len(got) != tt.want {
				t.Errorf("Validate() returned %d errors, want %d", len(got), tt.want)
				for _, e := range got {
					t.Logf("  %s", e.Error())
				}
			}
		})
	}
}

func TestSemanticErrorContext(t *testing.T) {
	t.Run("with consumer name", func(t *testing.T) {
		e := SemanticError{
			Got:          plugin.TypeStructured,
			Want:         plugin.TypeScoredEvent,
			StreamName:   "http",
			PipelineName: "main",
			ConsumerType: "sink",
			ConsumerName: "file-threat",
		}
		want := "stream 'http', pipeline 'main', sink 'file-threat': expects 'scored_event' but spine produces 'structured'"
		if got := e.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("with consumer name no stream", func(t *testing.T) {
		e := SemanticError{
			Got:          plugin.TypeStructured,
			Want:         plugin.TypeScoredEvent,
			PipelineName: "main",
			ConsumerType: "sink",
			ConsumerName: "file-threat",
		}
		want := "pipeline 'main', sink 'file-threat': expects 'scored_event' but spine produces 'structured'"
		if got := e.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without consumer name", func(t *testing.T) {
		e := SemanticError{
			StepIndex: 0,
			StepAName: "file",
			StepBName: "file-sink",
			Got:       plugin.TypeStructured,
			Want:      plugin.TypeScoredEvent,
		}
		want := "step 0: plugin 'file' outputs 'structured' but 'file-sink' expects 'scored_event'"
		if got := e.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestValidateSpine(t *testing.T) {
	t.Run("ETL no detectors — Scorer not added", func(t *testing.T) {
		ctx := PipelineContext{
			StreamName:   "http",
			PipelineName: "main",
			Spine: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
			},
		}
		produced, errs := ValidateSpine(ctx, false)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
		if produced != plugin.TypeStructured {
			t.Errorf("producedType = %q, want %q", produced, plugin.TypeStructured)
		}
	})

	t.Run("with detectors — Scorer appended, producedType=ScoredEvent", func(t *testing.T) {
		// Backing array with spare capacity (len 2, cap 3): a naive append in
		// ValidateSpine would write the scorer into backing[2], corrupting the
		// caller's array. The defensive copy must prevent that.
		backing := make([]plugin.Manifest, 2, 3)
		backing[0] = plugin.Manifest{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured}
		backing[1] = plugin.Manifest{PluginID: "probe", InputType: plugin.TypeStructured, OutputType: plugin.TypeStructured}
		ctx := PipelineContext{StreamName: "http", PipelineName: "main", Spine: backing}

		produced, errs := ValidateSpine(ctx, true)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
		if produced != plugin.TypeScoredEvent {
			t.Errorf("producedType = %q, want %q", produced, plugin.TypeScoredEvent)
		}
		// Aliasing guard: the spare backing slot must remain zero — not the scorer.
		if full := backing[:3]; full[2].PluginID == "scorer" {
			t.Error("ValidateSpine mutated the caller's backing array (slice-append aliasing bug)")
		}
	})

	t.Run("incompatible spine — error enriched with ConsumerType=spine", func(t *testing.T) {
		ctx := PipelineContext{
			StreamName:   "http",
			PipelineName: "main",
			Spine: []plugin.Manifest{
				{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				{PluginID: "probe", InputType: plugin.TypeScoredEvent, OutputType: plugin.TypeScoredEvent},
			},
		}
		_, errs := ValidateSpine(ctx, false)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		if errs[0].ConsumerType != "spine" {
			t.Errorf("ConsumerType = %q, want \"spine\"", errs[0].ConsumerType)
		}
		if errs[0].StreamName != "http" || errs[0].PipelineName != "main" {
			t.Errorf("stream/pipeline not enriched: %+v", errs[0])
		}
	})
}

func TestValidateTerminals(t *testing.T) {
	t.Run("sink matches produced type", func(t *testing.T) {
		ctx := PipelineContext{
			StreamName:   "http",
			PipelineName: "main",
			Sinks: []plugin.Manifest{
				{PluginID: "file-sink", InputType: plugin.TypeScoredEvent},
			},
		}
		errs := ValidateTerminals(ctx, plugin.TypeScoredEvent)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
	})

	t.Run("sink type mismatch", func(t *testing.T) {
		ctx := PipelineContext{
			StreamName:   "http",
			PipelineName: "main",
			Sinks: []plugin.Manifest{
				{PluginID: "file-sink", InputType: plugin.TypeStructured},
			},
		}
		errs := ValidateTerminals(ctx, plugin.TypeScoredEvent)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		if errs[0].ConsumerType != "sink" {
			t.Errorf("ConsumerType = %q, want \"sink\"", errs[0].ConsumerType)
		}
		if errs[0].ConsumerName != "file-sink" {
			t.Errorf("ConsumerName = %q, want \"file-sink\"", errs[0].ConsumerName)
		}
		if errs[0].Got != plugin.TypeScoredEvent || errs[0].Want != plugin.TypeStructured {
			t.Errorf("Got=%q Want=%q", errs[0].Got, errs[0].Want)
		}
	})

	t.Run("multiple sinks — independent errors", func(t *testing.T) {
		ctx := PipelineContext{
			StreamName:   "http",
			PipelineName: "main",
			Sinks: []plugin.Manifest{
				{PluginID: "ok-sink", InputType: plugin.TypeScoredEvent},
				{PluginID: "bad-sink", InputType: plugin.TypeStructured},
				{PluginID: "also-bad", InputType: plugin.TypeNone},
			},
		}
		errs := ValidateTerminals(ctx, plugin.TypeScoredEvent)
		if len(errs) != 2 {
			t.Fatalf("expected 2 errors, got %d", len(errs))
		}
		if errs[0].ConsumerName == "ok-sink" {
			t.Errorf("ok-sink should not produce an error")
		}
	})

	t.Run("TypeAny sink always compatible", func(t *testing.T) {
		ctx := PipelineContext{
			Sinks: []plugin.Manifest{
				{PluginID: "any-sink", InputType: plugin.TypeAny},
			},
		}
		errs := ValidateTerminals(ctx, plugin.TypeStructured)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
	})
}

func TestValidateErrorMessage(t *testing.T) {
	chain := []plugin.Manifest{
		{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
		{PluginID: "file-sink", InputType: plugin.TypeScoredEvent, OutputType: plugin.TypeNone},
	}

	errs := Validate(chain)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}

	msg := errs[0].Error()
	if msg != "step 0: plugin 'file' outputs 'structured' but 'file-sink' expects 'scored_event'" {
		t.Errorf("unexpected error message:\n  got:  %q\n  want: %q", msg, "step 0: plugin 'file' outputs 'structured' but 'file-sink' expects 'scored_event'")
	}
}

func TestValidateExecutorWiring(t *testing.T) {
	t.Run("matched channel — compatible", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1"}},
		}
		channelTypes := map[string]plugin.DataType{"ch1": plugin.TypeScoredEvent}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
	})

	t.Run("matched channel — type mismatch", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1"}},
		}
		channelTypes := map[string]plugin.DataType{"ch1": plugin.TypeStructured}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		if errs[0].ConsumerType != "executor" {
			t.Errorf("ConsumerType = %q, want \"executor\"", errs[0].ConsumerType)
		}
		if errs[0].ConsumerName != "cf" {
			t.Errorf("ConsumerName = %q, want \"cf\"", errs[0].ConsumerName)
		}
	})

	t.Run("unknown channel", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"missing"}},
		}
		channelTypes := map[string]plugin.DataType{}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		wantNote := "wired to unknown channel 'missing'"
		if errs[0].Note != wantNote {
			t.Errorf("Note = %q, want %q", errs[0].Note, wantNote)
		}
	})

	t.Run("no sources", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent},
		}
		errs := ValidateExecutorWiring(bindings, nil)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		if errs[0].Note != "has no sources" {
			t.Errorf("Note = %q, want \"has no sources\"", errs[0].Note)
		}
	})

	t.Run("TypeAny compatible", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "any-exec", InputType: plugin.TypeAny, SourceNames: []string{"ch1"}},
		}
		channelTypes := map[string]plugin.DataType{"ch1": plugin.TypeStructured}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(errs))
		}
	})

	t.Run("multiple sources", func(t *testing.T) {
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1", "missing"}},
		}
		channelTypes := map[string]plugin.DataType{"ch1": plugin.TypeScoredEvent}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		wantNote := "wired to unknown channel 'missing'"
		if errs[0].Note != wantNote {
			t.Errorf("Note = %q, want %q", errs[0].Note, wantNote)
		}
	})

	t.Run("channel has writer but no reader", func(t *testing.T) {
		// Писатель (sentinel-threat sink) зарегистрировал канал "orphan",
		// но ни один executor на него не подписан — очередь будет расти
		// бесконечно. Decision D2 требует fail-fast.
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1"}},
		}
		channelTypes := map[string]plugin.DataType{
			"ch1":    plugin.TypeScoredEvent,
			"orphan": plugin.TypeScoredEvent,
		}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d", len(errs))
		}
		if errs[0].ConsumerType != "channel" {
			t.Errorf("ConsumerType = %q, want \"channel\"", errs[0].ConsumerType)
		}
		if errs[0].ConsumerName != "orphan" {
			t.Errorf("ConsumerName = %q, want \"orphan\"", errs[0].ConsumerName)
		}
		wantNote := "has writer but no reader"
		if errs[0].Note != wantNote {
			t.Errorf("Note = %q, want %q", errs[0].Note, wantNote)
		}
	})

	t.Run("multiple channels — only unpaired ones error", func(t *testing.T) {
		// ch1 — ок (читается reader-1); ch2 — ок (читается reader-2);
		// ch3 и ch4 — orphan. Ожидаем две ошибки с правильными именами
		// и в стабильном лексикографическом порядке.
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1"}},
			{Name: "mk", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch2"}},
		}
		channelTypes := map[string]plugin.DataType{
			"ch1": plugin.TypeScoredEvent,
			"ch2": plugin.TypeScoredEvent,
			"ch3": plugin.TypeScoredEvent,
			"ch4": plugin.TypeScoredEvent,
		}
		errs := ValidateExecutorWiring(bindings, channelTypes)
		if len(errs) != 2 {
			t.Fatalf("expected 2 errors, got %d", len(errs))
		}
		if errs[0].ConsumerName != "ch3" || errs[1].ConsumerName != "ch4" {
			t.Errorf("error order = [%q, %q], want [ch3, ch4] (sorted)", errs[0].ConsumerName, errs[1].ConsumerName)
		}
	})

	t.Run("empty channelTypes — no orphan errors", func(t *testing.T) {
		// Если в конфиге вообще нет sink'ов, писать некому — нет и
		// "писатель без читателя". Все прочие проверки (unknown channel
		// и т.п.) отрабатывают по bindings.
		bindings := []ExecutorBinding{
			{Name: "cf", InputType: plugin.TypeScoredEvent, SourceNames: []string{"ch1"}},
		}
		errs := ValidateExecutorWiring(bindings, nil)
		if len(errs) != 1 {
			t.Fatalf("expected 1 error (unknown channel), got %d", len(errs))
		}
		if errs[0].Note != "wired to unknown channel 'ch1'" {
			t.Errorf("Note = %q", errs[0].Note)
		}
	})
}

func TestValidatePipelines(t *testing.T) {
	t.Run("single valid pipeline with detectors", func(t *testing.T) {
		pipes := []PipelineContext{
			{
				StreamName:   "http",
				PipelineName: "main",
				Spine: []plugin.Manifest{
					{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				},
				Sinks: []plugin.Manifest{
					{PluginID: "file-sink", InputType: plugin.TypeScoredEvent},
				},
			},
		}
		results := ValidatePipelines(pipes, []bool{true})
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].ProducedType != plugin.TypeScoredEvent {
			t.Errorf("ProducedType = %q, want %q", results[0].ProducedType, plugin.TypeScoredEvent)
		}
		if len(results[0].Errors) != 0 {
			t.Fatalf("expected 0 errors, got %d", len(results[0].Errors))
		}
	})

	t.Run("ETL pipeline no detectors", func(t *testing.T) {
		pipes := []PipelineContext{
			{
				StreamName:   "http",
				PipelineName: "main",
				Spine: []plugin.Manifest{
					{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				},
				Sinks: []plugin.Manifest{
					{PluginID: "file-sink", InputType: plugin.TypeScoredEvent},
				},
			},
		}
		results := ValidatePipelines(pipes, []bool{false})
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].ProducedType != plugin.TypeStructured {
			t.Errorf("ProducedType = %q, want %q", results[0].ProducedType, plugin.TypeStructured)
		}
		if len(results[0].Errors) != 1 {
			t.Fatalf("expected 1 error, got %d", len(results[0].Errors))
		}
	})

	t.Run("two pipelines", func(t *testing.T) {
		pipes := []PipelineContext{
			{
				StreamName:   "http",
				PipelineName: "main",
				Spine: []plugin.Manifest{
					{PluginID: "file", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				},
				Sinks: []plugin.Manifest{
					{PluginID: "file-sink", InputType: plugin.TypeScoredEvent},
				},
			},
			{
				StreamName:   "syslog",
				PipelineName: "etl",
				Spine: []plugin.Manifest{
					{PluginID: "syslog", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
				},
				Sinks: []plugin.Manifest{
					{PluginID: "es-sink", InputType: plugin.TypeStructured},
				},
			},
		}
		results := ValidatePipelines(pipes, []bool{true, false})
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].StreamName != "http" || results[0].PipelineName != "main" {
			t.Errorf("result[0] stream/pipeline mismatch")
		}
		if results[0].ProducedType != plugin.TypeScoredEvent {
			t.Errorf("result[0].ProducedType = %q, want %q", results[0].ProducedType, plugin.TypeScoredEvent)
		}
		if len(results[0].Errors) != 0 {
			t.Errorf("result[0] expected 0 errors, got %d", len(results[0].Errors))
		}
		if results[1].StreamName != "syslog" || results[1].PipelineName != "etl" {
			t.Errorf("result[1] stream/pipeline mismatch")
		}
		if results[1].ProducedType != plugin.TypeStructured {
			t.Errorf("result[1].ProducedType = %q, want %q", results[1].ProducedType, plugin.TypeStructured)
		}
		if len(results[1].Errors) != 0 {
			t.Errorf("result[1] expected 0 errors, got %d", len(results[1].Errors))
		}
	})

	t.Run("mismatched slice lengths panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic, got none")
			}
		}()
		ValidatePipelines([]PipelineContext{{}}, []bool{true, false})
	})
}
