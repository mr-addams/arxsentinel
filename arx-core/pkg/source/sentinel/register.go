// ========================== pkg/source/sentinel — Registration ============================
//   Self-registering source plugin entry point.
//   Регистрирует "sentinel" как input type в pkg/source registry.

package sentinel

import (
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

// init регистрирует "sentinel" source в глобальном registry.
// Вызывается автоматически при импорте пакета.
//
// Factory:
//
//	cfg.Addr   → "ncs://<queue-name>" (имя NCS-очереди)
//	opts.LogFn → log callback (nil допустим)
//
// BuildOptions.Parser игнорируется — sentinel-threat уже структура, parser не нужен.
func init() {
	pkgsource.Register("sentinel", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return New(cfg.Addr, opts.LogFn)
	})
	pkgsource.RegisterManifest("sentinel", (&SentinelSource{}).Manifest())
}
