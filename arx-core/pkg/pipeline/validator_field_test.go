// ========================== pkg/pipeline — Field-level validator tests ====================
//   Verifies the Phase 4 (Flow 083) field-level contract check: for every
//   adjacent producer/consumer pair, chain[i].Produces must be a superset of
//   chain[i+1].Consumes by Name (consumer's Required flag participates).
//
//   Back-compat rule (critical, also asserted here): the field-level check
//   activates ONLY when both adjacent plugins declare a non-empty field
//   contract. Empty Produces OR empty Consumes => type-only verdict, no
//   field errors — this preserves back-compat with manifests written
//   before FieldDecl was introduced (Flow 083 Phase 1.3).

package pipeline

import (
	"strings"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// helper: produces the envelope-style field set declared by every source
// in arx-core (file/stdin/http/syslog/sentinel after Phase 2.4). Using the
// real shape keeps the tests honest about what "satisfies the contract"
// looks like in production.
func envelopeProduces() []plugin.FieldDecl {
	return []plugin.FieldDecl{
		{Name: "Timestamp", Required: true},
		{Name: "Stream", Required: true},
		{Name: "Source", Required: true},
		{Name: "SourceType", Required: true},
	}
}

func TestValidateFields_BackCompat_EmptyProduces(t *testing.T) {
	// Producer declares no field contract (nil Produces). Consumer demands
	// required fields. Validator must NOT raise a field error — the
	// producer is "old-style" and falls back to the type-only verdict.
	chain := []plugin.Manifest{
		{PluginID: "old-producer", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
		{
			PluginID:   "consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes:   []plugin.FieldDecl{{Name: "Missing", Required: true}},
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("back-compat violation: empty Produces must skip field check, got %d errors: %v",
			len(errs), errs)
	}
}

func TestValidateFields_BackCompat_EmptyConsumes(t *testing.T) {
	// Producer declares field contract; consumer does not (nil Consumes).
	// Validator must NOT raise a field error — the consumer is "old-style".
	chain := []plugin.Manifest{
		{
			PluginID:   "new-producer",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "old-consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			// Consumes intentionally nil.
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("back-compat violation: empty Consumes must skip field check, got %d errors: %v",
			len(errs), errs)
	}
}

func TestValidateFields_BackCompat_BothEmpty(t *testing.T) {
	// Both sides old-style: nothing declared on either side. Same as the
	// pre-Phase-4 baseline — no field errors, type check still applies.
	chain := []plugin.Manifest{
		{PluginID: "old-src", InputType: plugin.TypeNone, OutputType: plugin.TypeStructured},
		{PluginID: "old-sink", InputType: plugin.TypeStructured, OutputType: plugin.TypeNone},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("back-compat violation: both empty must skip field check, got %d errors: %v",
			len(errs), errs)
	}
}

func TestValidateFields_Satisfied(t *testing.T) {
	// Producer emits all required envelope fields; consumer requires the
	// same set. Field check must be silent (no errors).
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes:   envelopeProduces(),
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("satisfied contract must not produce errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateFields_ProducerSubset_Satisfied(t *testing.T) {
	// Producer emits a superset of what the consumer requires. Valid:
	// extra fields in Produces are harmless (consumer does not ask for
	// them, so extra output is not a contract violation).
	chain := []plugin.Manifest{
		{
			PluginID:  "rich-producer",
			InputType: plugin.TypeNone, OutputType: plugin.TypeStructured,
			Produces: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true},
				{Name: "Stream", Required: true},
				{Name: "Source", Required: true},
				{Name: "SourceType", Required: true},
				{Name: "Extra", Required: false}, // extra, harmless
			},
		},
		{
			PluginID:  "minimal-consumer",
			InputType: plugin.TypeStructured, OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true},
			},
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("producer-superset must not produce errors, got %d: %v", len(errs), errs)
	}
}

func TestValidateFields_RequiredMissing_SemanticError(t *testing.T) {
	// Consumer requires "Line" but the producer only emits envelope
	// fields. Field check MUST raise one SemanticError with a Note that
	// names both plugin IDs and the missing field.
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "security-processor",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true}, // present
				{Name: "Line", Required: true},      // MISSING
			},
		},
	}
	errs := Validate(chain)
	if len(errs) != 1 {
		t.Fatalf("expected 1 field error, got %d: %v", len(errs), errs)
	}

	e := errs[0]
	// StepIndex must match the pair index in the chain (0 here).
	if e.StepIndex != 0 {
		t.Errorf("StepIndex = %d, want 0", e.StepIndex)
	}
	if e.StepAName != "file" {
		t.Errorf("StepAName = %q, want \"file\"", e.StepAName)
	}
	if e.StepBName != "security-processor" {
		t.Errorf("StepBName = %q, want \"security-processor\"", e.StepBName)
	}

	// Error() output (consumerless path) must mention both plugin IDs and
	// the missing field name.
	msg := e.Error()
	for _, must := range []string{"file", "security-processor", "Line"} {
		if !strings.Contains(msg, must) {
			t.Errorf("Error() = %q, must contain %q", msg, must)
		}
	}

	// Got/Want are NOT used for field errors — type-level fields stay zero.
	if e.Got != "" || e.Want != "" {
		t.Errorf("field error should leave Got/Want empty, got Got=%q Want=%q", e.Got, e.Want)
	}
}

func TestValidateFields_MultipleRequiredMissing_OneErrorPerField(t *testing.T) {
	// Consumer requires three fields; producer emits none of them. The
	// validator must raise three SemanticErrors — one per missing field —
	// so the operator can fix all mismatches in one pass instead of
	// iterating (startup -> fix -> restart).
	chain := []plugin.Manifest{
		{
			PluginID:   "minimal-producer",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces: []plugin.FieldDecl{
				{Name: "Stream", Required: true},
			},
		},
		{
			PluginID:   "hungry-consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true},
				{Name: "Source", Required: true},
				{Name: "SourceType", Required: true},
			},
		},
	}
	errs := Validate(chain)
	if len(errs) != 3 {
		t.Fatalf("expected 3 field errors (one per missing required), got %d: %v", len(errs), errs)
	}

	// Each missing field must appear exactly once across the error set.
	seen := map[string]bool{}
	for _, e := range errs {
		for _, f := range []string{"Timestamp", "Source", "SourceType"} {
			if strings.Contains(e.Error(), "'"+f+"'") {
				if seen[f] {
					t.Errorf("field %q reported more than once", f)
				}
				seen[f] = true
			}
		}
	}
	for _, f := range []string{"Timestamp", "Source", "SourceType"} {
		if !seen[f] {
			t.Errorf("field %q not reported in any error", f)
		}
	}
}

func TestValidateFields_OptionalNotSatisfied_NoError(t *testing.T) {
	// Consumer lists "Line" as Optional (Required: false). Producer does
	// NOT emit "Line". Optional accepts absence — this must NOT be an
	// error (consumer "accepts but does not require").
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(), // no "Line"
		},
		{
			PluginID:   "optional-consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true},
				{Name: "Line", Required: false}, // optional, absent is fine
			},
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("optional Consumes absence must not error, got %d: %v", len(errs), errs)
	}
}

func TestValidateFields_MixedRequiredOptional_OnlyRequiredChecked(t *testing.T) {
	// Consumer requires "Timestamp" (present) and optionally wants
	// "Line" (absent). No errors expected — the Required one is satisfied,
	// the Optional one is absent.
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "mixed-consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true},
				{Name: "Line", Required: false},
			},
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("mixed-required/optional must not error when Required satisfied, got %d: %v",
			len(errs), errs)
	}
}

func TestValidateFields_ProducerRequiredFlagIgnored(t *testing.T) {
	// The producer lists the required field BUT marks it Required:false.
	// Per FieldDecl godoc, the producer's own Required flag is ignored
	// for the match — only the consumer's Required matters. Producer
	// listing X by Name satisfies the contract regardless of producer's
	// Required flag value.
	chain := []plugin.Manifest{
		{
			PluginID:  "lenient-producer",
			InputType: plugin.TypeNone, OutputType: plugin.TypeStructured,
			Produces: []plugin.FieldDecl{
				{Name: "Timestamp", Required: false}, // producer's flag ignored
				{Name: "Stream", Required: false},
				{Name: "Source", Required: false},
				{Name: "SourceType", Required: false},
			},
		},
		{
			PluginID:  "strict-consumer",
			InputType: plugin.TypeStructured, OutputType: plugin.TypeStructured,
			Consumes: []plugin.FieldDecl{
				{Name: "Timestamp", Required: true}, // consumer's flag controls
				{Name: "Stream", Required: true},
				{Name: "Source", Required: true},
				{Name: "SourceType", Required: true},
			},
		},
	}
	if errs := Validate(chain); len(errs) != 0 {
		t.Fatalf("producer's Required flag must be ignored for the match, got %d: %v",
			len(errs), errs)
	}
}

func TestValidateFields_MultipleAdjacentPairs_PerPairIndependence(t *testing.T) {
	// Three-step chain: file -> good-processor -> bad-consumer.
	// Pair (file, good-processor): satisfied, no error.
	// Pair (good-processor, bad-consumer): missing required field, 1 error.
	// Total: exactly one field error, at StepIndex=1.
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "good-processor",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
			Consumes:   envelopeProduces(), // satisfied by file
		},
		{
			PluginID:   "bad-consumer",
			InputType:  plugin.TypeStructured,
			OutputType: plugin.TypeScoredEvent,
			Produces:   nil,
			Consumes: []plugin.FieldDecl{
				{Name: "Line", Required: true}, // missing from good-processor
			},
		},
	}
	errs := Validate(chain)
	if len(errs) != 1 {
		t.Fatalf("expected 1 field error at step 1, got %d: %v", len(errs), errs)
	}
	if errs[0].StepIndex != 1 {
		t.Errorf("StepIndex = %d, want 1", errs[0].StepIndex)
	}
	if errs[0].StepAName != "good-processor" {
		t.Errorf("StepAName = %q, want \"good-processor\"", errs[0].StepAName)
	}
	if errs[0].StepBName != "bad-consumer" {
		t.Errorf("StepBName = %q, want \"bad-consumer\"", errs[0].StepBName)
	}
	if !strings.Contains(errs[0].Error(), "Line") {
		t.Errorf("Error() must mention field 'Line', got %q", errs[0].Error())
	}
}

func TestValidateFields_CombineWithTypeError(t *testing.T) {
	// Type mismatch (Structured -> ScoredEvent) AND field mismatch in the
	// same pair. Both errors must be reported independently so the
	// operator sees the full picture in one startup pass.
	chain := []plugin.Manifest{
		{
			PluginID:   "file",
			InputType:  plugin.TypeNone,
			OutputType: plugin.TypeStructured,
			Produces:   envelopeProduces(),
		},
		{
			PluginID:   "hungry-bad-input",
			InputType:  plugin.TypeScoredEvent, // wrong type
			OutputType: plugin.TypeScoredEvent,
			Consumes: []plugin.FieldDecl{
				{Name: "Line", Required: true}, // also missing
			},
		},
	}
	errs := Validate(chain)
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors (1 type + 1 field), got %d: %v", len(errs), errs)
	}

	var hasTypeErr, hasFieldErr bool
	for _, e := range errs {
		if e.Note == "" {
			// type-level: has Got/Want populated
			hasTypeErr = true
			if e.Got != plugin.TypeStructured || e.Want != plugin.TypeScoredEvent {
				t.Errorf("type error Got=%q Want=%q, want Structured/ScoredEvent",
					e.Got, e.Want)
			}
		} else {
			hasFieldErr = true
			if !strings.Contains(e.Error(), "Line") {
				t.Errorf("field error must mention 'Line', got %q", e.Error())
			}
		}
	}
	if !hasTypeErr {
		t.Error("missing type error")
	}
	if !hasFieldErr {
		t.Error("missing field error")
	}
}

func TestValidateFields_EmptyChain_NoFieldPanic(t *testing.T) {
	// Edge case: empty chain must not panic and must not call validateFields
	// (no pairs to check). Defensive: the for-loop ranges [0, len-1) which
	// is empty for len < 2.
	if errs := Validate(nil); len(errs) != 0 {
		t.Errorf("empty chain must return nil, got %v", errs)
	}
}

func TestValidateSpine_FieldErrorEnrichedLikeTypeError(t *testing.T) {
	// ValidateSpine ranges over errs and sets StreamName/PipelineName/
	// ConsumerType on every entry — field errors must flow through that
	// loop just like type errors do (the brief is explicit: "validate
	// signature needs to change in a breaking way" is a gray-zone
	// trigger, so enrichment must remain shared).
	ctx := PipelineContext{
		StreamName:   "http",
		PipelineName: "main",
		Spine: []plugin.Manifest{
			{
				PluginID:   "file",
				InputType:  plugin.TypeNone,
				OutputType: plugin.TypeStructured,
				Produces:   envelopeProduces(),
			},
			{
				PluginID:   "hungry-detector",
				InputType:  plugin.TypeStructured,
				OutputType: plugin.TypeStructured,
				Consumes: []plugin.FieldDecl{
					{Name: "Line", Required: true},
				},
			},
		},
	}
	_, errs := ValidateSpine(ctx)
	if len(errs) != 1 {
		t.Fatalf("expected 1 field error, got %d: %v", len(errs), errs)
	}
	e := errs[0]
	if e.StreamName != "http" {
		t.Errorf("StreamName = %q, want \"http\" (enrichment must apply to field errors)", e.StreamName)
	}
	if e.PipelineName != "main" {
		t.Errorf("PipelineName = %q, want \"main\"", e.PipelineName)
	}
	if e.ConsumerType != "spine" {
		t.Errorf("ConsumerType = %q, want \"spine\"", e.ConsumerType)
	}
}

func TestValidateFields_ZeroAllocationHint_NilOnSuccess(t *testing.T) {
	// validateFields must return a nil slice (not an empty slice) on the
	// success path so the caller's `if len(fieldErrs) > 0` check is exact
	// and the errs slice is not grown unnecessarily. This is the
	// no-allocation-on-success contract from the brief.
	producer := plugin.Manifest{
		PluginID:  "p",
		Produces:  envelopeProduces(),
	}
	consumer := plugin.Manifest{
		PluginID: "c",
		Consumes: envelopeProduces(),
	}
	got := validateFields(producer, consumer, 0)
	if got != nil {
		t.Errorf("validateFields on success must return nil, got %v (len=%d)", got, len(got))
	}
}
