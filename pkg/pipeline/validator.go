// ========================== pkg/pipeline — Pipeline validator ===============================
//   Validates data type compatibility between adjacent plugins in a pipeline chain.
//   Each pair (i, i+1) is checked: chain[i].OutputType must match chain[i+1].InputType.
//   TypeAny is universally compatible — it bridges any type on either side.
//   Also provides topology-aware validation: ValidateSpine checks the producing chain
//   (Source → Processors → Detectors → [synthetic Scorer]), and ValidateTerminals checks
//   each sink independently against the spine's produced type.

package pipeline

import "github.com/mr-addams/arxsentinel/pkg/plugin"

// SemanticError describes a type mismatch between two adjacent pipeline steps.
type SemanticError struct {
	StepIndex int
	StepAName string
	StepBName string
	Got       plugin.DataType
	Want      plugin.DataType

	StreamName   string // stream name; empty for single-stream configs
	PipelineName string // pipeline name
	ConsumerType string // "sink" | "executor" | "spine"
	ConsumerName string // consumer plugin name for terminal errors
	Note         string // optional override: when set, Error() uses this instead of mismatch format
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
type PipelineContext struct {
	StreamName   string
	PipelineName string
	Spine        []plugin.Manifest // Source → [Processors] → [Detectors] → [synthetic Scorer]
	Sinks        []plugin.Manifest // terminal sinks of this pipeline
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

// ExecutorBinding describes a top-level executor and the NCH channels it reads from
// for wiring validation. Constructed from config by the caller (validate.go).
type ExecutorBinding struct {
	Name        string          // executor instance name (executor.name)
	InputType   plugin.DataType // executor's InputType from ManifestByName
	SourceNames []string        // NCH channel names from executor.Sources[].Name
}

// ValidatePipelines runs ValidateSpine + ValidateTerminals for each pipeline.
// Returns one PipelineResult per pipeline (may have zero errors).
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

// ValidateExecutorWiring checks each executor's InputType against the produced
// type of the sentinel-threat sink channel it is wired to.
// channelTypes: map of sentinel-threat sink name → produced DataType (TypeScoredEvent).
func ValidateExecutorWiring(bindings []ExecutorBinding, channelTypes map[string]plugin.DataType) []SemanticError {
	var errs []SemanticError
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