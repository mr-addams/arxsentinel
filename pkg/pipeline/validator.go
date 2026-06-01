// ========================== pkg/pipeline — Pipeline validator ===============================
//   Validates data type compatibility between adjacent plugins in a pipeline chain.
//   Each pair (i, i+1) is checked: chain[i].OutputType must match chain[i+1].InputType.
//   TypeAny is universally compatible — it bridges any type on either side.

package pipeline

import "github.com/mr-addams/arxsentinel/pkg/plugin"

// SemanticError describes a type mismatch between two adjacent pipeline steps.
type SemanticError struct {
	StepIndex int
	StepAName string
	StepBName string
	Got       plugin.DataType
	Want      plugin.DataType
}

// Error returns a human-readable description of the type mismatch.
func (e SemanticError) Error() string {
	return "step " + itoa(e.StepIndex) + ": plugin '" + e.StepAName +
		"' outputs '" + string(e.Got) + "' but '" + e.StepBName +
		"' expects '" + string(e.Want) + "'"
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