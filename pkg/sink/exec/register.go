// ========================== pkg/sink/exec — registration ====================================
//   Registers the "exec" sink type with the global sink registry.
//   Delegates to execplugin.NewSink for actual implementation.

package exec

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/pkg/execplugin"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

func init() {
	pkgsink.Register("exec", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		if cfg.Exec == "" {
			return nil, fmt.Errorf("sink type=exec requires exec field (path to plugin binary)")
		}
		return execplugin.NewSink(cfg.Exec)
	})
	pkgsink.RegisterManifest("exec", (&execplugin.ExecSink{}).Manifest())
}