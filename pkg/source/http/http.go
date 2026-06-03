package http

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

func init() {
	pkgsource.Register("http", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return nil, fmt.Errorf("http source: not implemented")
	})
	pkgsource.RegisterManifest("http", plugin.Manifest{
		PluginID:      "http",
		PluginVersion: "0.1.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
	})
}