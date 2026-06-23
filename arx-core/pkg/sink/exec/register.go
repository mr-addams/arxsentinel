// ========================== pkg/sink/exec — registration ====================================
//   Registers the "exec" sink type with the global sink registry.
//   Delegates to execplugin.NewSink for actual implementation.

package exec

import (
	"context"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/execplugin"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
)

func init() {
	pkgsink.Register("exec", func(ctx context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		if cfg.Exec == "" {
			return nil, fmt.Errorf("sink type=exec requires exec field (path to plugin binary)")
		}
		// ctx проброшен в NewSink → NewManagedProcess — спавн subprocess'а
		// теперь отменяется по сигналу (SIGHUP/SIGTERM), а не висит вечно
		// при зависшем бинарнике.
		return execplugin.NewSink(ctx, cfg.Exec)
	})
	pkgsink.RegisterManifest("exec", (&execplugin.ExecSink{}).Manifest())
}
