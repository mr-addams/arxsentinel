// ========================== pkg/pipeline — Pipeline validator tests =========================

package pipeline

import (
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
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