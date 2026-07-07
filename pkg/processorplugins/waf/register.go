// ========================== pkg/processor/waf — Registration ===============================
//
//	Self-registration of WafProcessor in the processor registry (Flow 001, Task H1/H3).
//
//	The factory extracts dependencies from ProcessorConfig.Params:
//	  "waf_config" → waf.Config  (the parsed WAF rules: name + expression + action)
//
//	The pipeline bootstrapper (main.go or wire-up code) sets these keys before calling
//	processor.Build("waf", cfg).
//
//	No panic recovery is needed: the type assertion below uses comma-ok and
//	never panics on a missing or wrong-type param, and NewWafProcessor returns
//	errors rather than panicking on bad rule expressions. The factory is also
//	invoked at wire-up time (not from init()), so a failure here surfaces as
//	an ordinary error to the caller that wired the plugin.
package waf

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/processor"
)

// ParamKeyConfig is the ProcessorConfig.Params key for waf.Config.
const ParamKeyConfig = "waf_config"

func init() {
	processor.Register("waf", factory)
}

// factory converts ProcessorConfig to waf.Config and creates the processor.
// Compiles the ruleset at Init time — a bad expression fails fast, returning
// an error rather than silently skipping the rule (DECISION D13).
func factory(cfg processor.ProcessorConfig) (plugin.Processor, error) {
	wc, ok := cfg.Params[ParamKeyConfig].(Config)
	if !ok {
		return nil, fmt.Errorf("waf: param %q missing or type-assert fails (got %T)", ParamKeyConfig, cfg.Params[ParamKeyConfig])
	}
	if ds, ok := cfg.Params["waf_drop_score"].(int); ok {
		wc.DropScore = ds
	}
	if tw, ok := cfg.Params["waf_tag_weights"].(map[string]int); ok {
		wc.TagWeights = tw
	}
	return NewWafProcessor(wc)
}
