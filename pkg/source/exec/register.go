package exec

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/pkg/execplugin"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

func init() {
	pkgsource.Register("exec", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		if cfg.Exec == "" {
			return nil, fmt.Errorf("source type=exec requires exec field (path to plugin binary)")
		}
		return execplugin.NewSource(cfg.Exec)
	})
}