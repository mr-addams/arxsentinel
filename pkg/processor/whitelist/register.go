// ========================== Module pkg/processor/whitelist/register =======================
//   Self-registration of WhitelistProcessor in the processor registry.
//
//   The factory extracts dependencies from ProcessorConfig.Params:
//     "whitelist_config" → config.WhitelistConfig  (the parsed whitelist YAML section)
//     "resolver"         → whitelist.Resolver      (DNS resolver for bot verification)
//
//   The pipeline bootstrapper (main.go or wire-up code) sets these keys before calling
//   processor.Build("whitelist", cfg).

package whitelist

import (
	"fmt"

	corewhitelist "github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arxsentinel/pkg/processor"
)

const (
	// ParamKeyWhitelistConfig is the ProcessorConfig.Params key for config.WhitelistConfig.
	ParamKeyWhitelistConfig = "whitelist_config"
	// ParamKeyResolver is the ProcessorConfig.Params key for the DNS resolver.
	ParamKeyResolver = "resolver"
)

func init() {
	processor.Register("whitelist", factory)
}

func factory(cfg processor.ProcessorConfig) (proc plugin.Processor, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("whitelist: factory panic: %v", r)
		}
	}()

	wc, ok := cfg.Params[ParamKeyWhitelistConfig].(config.WhitelistConfig)
	if !ok {
		return nil, fmt.Errorf("whitelist: param %q missing or type-assert fails", ParamKeyWhitelistConfig)
	}
	resolver, ok := cfg.Params[ParamKeyResolver].(corewhitelist.Resolver)
	if !ok {
		return nil, fmt.Errorf("whitelist: param %q missing or type-assert fails", ParamKeyResolver)
	}
	return NewWhitelistProcessor(wc, resolver)
}
