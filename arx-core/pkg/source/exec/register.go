// ========================== pkg/source/exec — registration =====================================
//   Registers the "exec" source type with the global source registry.
//   Delegates to execplugin.NewSource for actual implementation.

package exec

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/execplugin"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

func init() {
	pkgsource.Register("exec", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		if cfg.Exec == "" {
			return nil, fmt.Errorf("source type=exec requires exec field (path to plugin binary)")
		}
		return execplugin.NewSource(cfg.Exec)
	})
	pkgsource.RegisterManifest("exec", (&execplugin.ExecSource{}).Manifest())
}
