// ========================== pkg/pipeline — Pipeline validator ===============================
//   Validates data type compatibility between adjacent plugins in a pipeline chain.
//   Each pair (i, i+1) is checked: chain[i].OutputType must match chain[i+1].InputType.
//   TypeAny is universally compatible — it bridges any type on either side.
//   Also provides topology-aware validation: ValidateSpine checks the producing chain
//   (Source → Processors → Detectors → [synthetic Scorer]), and ValidateTerminals checks
//   each sink independently against the spine's produced type.

package pipeline

import (
	"sort"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// SemanticError describes a type mismatch between two adjacent pipeline steps.
// Consumer: validate.go (pipeline validation), main.go (config error reporting).
type SemanticError struct {
	StepIndex int             // Internal — step index in chain. Consumer: Error
	StepAName string          // Internal — first plugin name. Consumer: Error
	StepBName string          // Internal — second plugin name. Consumer: Error
	Got       plugin.DataType // YAML: — output type of first plugin. Consumer: Error
	Want      plugin.DataType // YAML: — input type of second plugin. Consumer: Error

	StreamName   string // YAML: streams[i].name — stream name; empty for single-stream configs. Consumer: Error
	PipelineName string // YAML: pipelines[i].name — pipeline name. Consumer: Error
	ConsumerType string // Internal — "sink" | "executor" | "spine". Consumer: Error
	ConsumerName string // YAML: sinks[i].name — consumer plugin name for terminal errors. Consumer: Error
	Note         string // YAML: — optional override: when set, Error() uses this instead of mismatch format. Consumer: Error
}

// Error returns a human-readable description of the type mismatch.
// When Note is set, it overrides the standard mismatch message:
//
//	executor 'cf-ban': has no sources
//
// When ConsumerName is non-empty (without Note), a context-rich format is used:
//
//	stream 'http', pipeline 'main', sink 'file-threat': expects 'scored_event' but spine produces 'structured'
//
// With empty ConsumerName the legacy format is preserved for backward compatibility.
func (e SemanticError) Error() string {
	if e.Note != "" && e.ConsumerName != "" {
		s := ""
		if e.StreamName != "" {
			s = "stream '" + e.StreamName + "', "
		}
		s += "pipeline '" + e.PipelineName + "', " + e.ConsumerType + " '" + e.ConsumerName +
			"': " + e.Note
		return s
	}
	if e.Note != "" {
		return e.Note
	}
	if e.ConsumerName != "" {
		s := ""
		if e.StreamName != "" {
			s = "stream '" + e.StreamName + "', "
		}
		s += "pipeline '" + e.PipelineName + "', " + e.ConsumerType + " '" + e.ConsumerName +
			"': expects '" + string(e.Want) + "' but spine produces '" + string(e.Got) + "'"
		return s
	}
	return "step " + itoa(e.StepIndex) + ": plugin '" + e.StepAName +
		"' outputs '" + string(e.Got) + "' but '" + e.StepBName +
		"' expects '" + string(e.Want) + "'"
}

// PipelineContext carries one pipeline's stages for validation.
// Consumer: validate.go, main.go.
type PipelineContext struct {
	StreamName   string            // YAML: streams[i].name — stream identifier. Consumer: ValidateSpine, ValidateTerminals
	PipelineName string            // YAML: pipelines[i].name — pipeline identifier. Consumer: ValidateSpine, ValidateTerminals
	Spine        []plugin.Manifest // YAML: — Source → [Processors] → [Detectors] → [synthetic Scorer]. Consumer: ValidateSpine
	Sinks        []plugin.Manifest // YAML: — terminal sinks of this pipeline. Consumer: ValidateTerminals
}

// PipelineResult holds validation errors for one pipeline plus the type its spine
// produces (Structured for ETL, ScoredEvent when scoring is active). Callers reuse
// ProducedType to validate executor wiring without recomputing the spine.
type PipelineResult struct {
	StreamName   string
	PipelineName string
	ProducedType plugin.DataType
	Errors       []SemanticError
}

// scorerManifest is the synthetic manifest for the core Scorer (not a plugin).
// It transforms detector output (Structured) into ScoredEvent. Added to the spine
// only when the pipeline has detectors (see hasDetectors arg).
var scorerManifest = plugin.Manifest{
	PluginID:   "scorer",
	Role:       plugin.RoleProcessor,
	InputType:  plugin.TypeStructured,
	OutputType: plugin.TypeScoredEvent,
}

// ValidateSpine validates the producing spine: Source → Processors → Detectors → [Scorer].
// When hasDetectors is true, the synthetic Scorer is appended so the spine ends at ScoredEvent.
// Returns the spine's final OutputType (the "produced type") and any compatibility errors,
// each enriched with stream/pipeline context (ConsumerType="spine").
//
// Non-destructive: ctx.Spine is never modified — when the Scorer is appended, a fresh
// slice is allocated so the caller's underlying array is not aliased.
// An empty spine yields produced type TypeNone; the caller should treat that as a
// configuration error (no source) before running ValidateTerminals.
// Called from: validate.go, main.go.
//
// Non-blocking.
func ValidateSpine(ctx PipelineContext, hasDetectors bool) (plugin.DataType, []SemanticError) {
	spine := ctx.Spine
	if hasDetectors {
		// Defensive copy: append into a new array so ctx.Spine (and its backing
		// array, which may have spare capacity) is never mutated for the caller.
		spine = make([]plugin.Manifest, len(ctx.Spine), len(ctx.Spine)+1)
		copy(spine, ctx.Spine)
		spine = append(spine, scorerManifest)
	}

	errs := Validate(spine)
	for i := range errs {
		errs[i].StreamName = ctx.StreamName
		errs[i].PipelineName = ctx.PipelineName
		errs[i].ConsumerType = "spine"
	}

	producedType := plugin.TypeNone
	if len(spine) > 0 {
		producedType = spine[len(spine)-1].OutputType
	}

	return producedType, errs
}

// ValidateTerminals checks each terminal consumer independently against the
// spine's produced type. Terminals are a fan-out (multiple sinks all consuming
// the same type) — they are NOT chained to each other.
// Called from: validate.go, main.go.
//
// Non-blocking.
func ValidateTerminals(ctx PipelineContext, producedType plugin.DataType) []SemanticError {
	var errs []SemanticError
	for _, m := range ctx.Sinks {
		if m.InputType == plugin.TypeAny || producedType == plugin.TypeAny {
			continue
		}
		if m.InputType != producedType {
			errs = append(errs, SemanticError{
				Got:          producedType,
				Want:         m.InputType,
				StreamName:   ctx.StreamName,
				PipelineName: ctx.PipelineName,
				ConsumerType: "sink",
				ConsumerName: m.PluginID,
			})
		}
	}
	return errs
}

// ExecutorBinding describes a top-level executor and the NCS channels it reads from
// for wiring validation. Constructed from config by the caller (validate.go).
// Consumer: main.go (executor wiring).
type ExecutorBinding struct {
	Name        string          // YAML: executors[i].name — executor instance name. Consumer: ValidateExecutorWiring
	InputType   plugin.DataType // YAML: — executor's InputType from ManifestByName. Consumer: ValidateExecutorWiring
	SourceNames []string        // YAML: executors[i].sources[].name — NCS channel names. Consumer: ValidateExecutorWiring
}

// ValidatePipelines runs ValidateSpine + ValidateTerminals for each pipeline.
// Returns one PipelineResult per pipeline (may have zero errors).
// Called from: main.go.
//
// Non-blocking.
func ValidatePipelines(pipes []PipelineContext, hasDetectors []bool) []PipelineResult {
	if len(pipes) != len(hasDetectors) {
		panic("pkg/pipeline: ValidatePipelines called with mismatched slice lengths")
	}
	results := make([]PipelineResult, 0, len(pipes))
	for i, ctx := range pipes {
		produced, errs := ValidateSpine(ctx, hasDetectors[i])
		termErrs := ValidateTerminals(ctx, produced)
		if len(termErrs) > 0 {
			errs = append(errs, termErrs...)
		}
		results = append(results, PipelineResult{
			StreamName:   ctx.StreamName,
			PipelineName: ctx.PipelineName,
			ProducedType: produced,
			Errors:       errs,
		})
	}
	return results
}

// ValidateExecutorWiring performs three fail-fast checks on the NamedChannelSwitch
// graph (decision D2, flow 061):
//
//  1. Every executor has at least one source channel configured (else it can never run).
//  2. Every channel an executor references exists in channelTypes (i.e. some
//     sentinel-threat sink writes to it). Otherwise the executor is "reader without
//     writer" — it would block forever on Pop() at runtime.
//  3. Every channel that has a writer (sentinel-threat sink) has at least one
//     executor reading from it. Otherwise the sink is "writer without reader" —
//     an unbounded queue that grows without bound (memory leak on memory/bbolt,
//     network/Redis pressure on the redis backend).
//
// Per-binding InputType compatibility (rule: producedType == b.InputType) is also
// enforced for every (binding, sourceName) pair once both ends of the wire exist.
//
// channelTypes: map of sentinel-threat sink name → produced DataType. Only
// sentinel-threat sinks feed the NamedChannelSwitch; other sinks (file, es, ...)
// write to their own backend and are out of scope for wiring validation.
// Called from: main.go.
//
// Non-blocking.
func ValidateExecutorWiring(bindings []ExecutorBinding, channelTypes map[string]plugin.DataType) []SemanticError {
	// Сначала собираем множество имён каналов, к которым подключён хотя бы один
	// executor. Используется в шаге 3 для обнаружения "писатель без читателя".
	readChannels := make(map[string]struct{}, len(bindings))
	for _, b := range bindings {
		for _, srcName := range b.SourceNames {
			readChannels[srcName] = struct{}{}
		}
	}

	// Шаг 3 (writer-without-reader): для каждого зарегистрированного writer'а
	// проверяем, что нашёлся хотя бы один reader. Проходим по детерминированному
	// списку ключей — map сама по себе в Go итерируется в случайном порядке,
	// что давало бы нестабильные сообщения об ошибках между запусками.
	writtenNames := make([]string, 0, len(channelTypes))
	for name := range channelTypes {
		writtenNames = append(writtenNames, name)
	}
	// sort.Slice (а не sort.Strings) не аллоцирует на каждом вызове:
	// sort.Strings использует sort.Sort + StringSlice, который каждый раз
	// аллоцирует лямбду. Валидация запускается один раз на старте, но
	// вынос константы поведения в sort.Slice делает код явно декларативным.
	sort.Slice(writtenNames, func(i, j int) bool { return writtenNames[i] < writtenNames[j] })

	var errs []SemanticError
	for _, name := range writtenNames {
		if _, read := readChannels[name]; read {
			continue
		}
		errs = append(errs, SemanticError{
			ConsumerType: "channel",
			ConsumerName: name,
			Note:         "has writer but no reader",
		})
	}

	// Шаги 1, 2 и проверка совместимости типов для каждой привязки.
	for _, b := range bindings {
		if len(b.SourceNames) == 0 {
			errs = append(errs, SemanticError{
				ConsumerType: "executor",
				ConsumerName: b.Name,
				Note:         "has no sources",
			})
			continue
		}
		for _, srcName := range b.SourceNames {
			producedType, ok := channelTypes[srcName]
			if !ok {
				// reader-without-writer: канал, на который ссылается executor,
				// не зарегистрирован ни одним sentinel-threat sink'ом.
				errs = append(errs, SemanticError{
					Got:          plugin.TypeNone,
					Want:         b.InputType,
					ConsumerType: "executor",
					ConsumerName: b.Name,
					Note:         "wired to unknown channel '" + srcName + "'",
				})
				continue
			}
			if producedType == plugin.TypeAny || b.InputType == plugin.TypeAny {
				continue
			}
			if producedType != b.InputType {
				errs = append(errs, SemanticError{
					Got:          producedType,
					Want:         b.InputType,
					ConsumerType: "executor",
					ConsumerName: b.Name,
				})
			}
		}
	}
	return errs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Validate checks type compatibility between adjacent plugins in a pipeline.
// Rule: chain[i].OutputType must equal chain[i+1].InputType.
// TypeAny is compatible with any type on either side.
// Returns nil if chain has fewer than 2 elements.
// Called from: ValidateSpine.
//
// Non-blocking.
func Validate(chain []plugin.Manifest) []SemanticError {
	if len(chain) < 2 {
		return nil
	}

	var errs []SemanticError
	for i := 0; i < len(chain)-1; i++ {
		got := chain[i].OutputType
		want := chain[i+1].InputType

		if got == plugin.TypeAny || want == plugin.TypeAny {
			continue
		}
		if got == want {
			continue
		}

		errs = append(errs, SemanticError{
			StepIndex: i,
			StepAName: chain[i].PluginID,
			StepBName: chain[i+1].PluginID,
			Got:       got,
			Want:      want,
		})
	}

	return errs
}
