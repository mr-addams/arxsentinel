// ========================== Shared resources — product-side singleton container ============
//
//	This file holds ONLY the singleton container shared between the product handler
//	(cmd/arxsentinel/processor_security.go), its builder (processor_factory.go),
//	and detector factories (builders.go).
//
//	WHAT IS HERE:
//	  - SharedResources          — product-side singleton container (blocklist,
//	                               chain-check, warnings writer); converted into
//	                               runtime.SharedResources in main.go via
//	                               bridgeRuntimeShared (processor_factory.go).
//
//	HISTORY: before Phase 3 of Flow 081, runStream / runPipeline / processLine
//	and the PipelineContext type also lived here. After extracting the runtime engine
//	into arx-core/pkg/runtime, those functions and the type were removed; only the
//	SharedResources DTO remains in their place.
package main

import (
	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/internal/core/output"
)

// SharedResources holds singleton dependencies shared across all streams.
// It is created once in main() before the streams start; it is passed to
// securityFactory through runtime.SharedResources (see bridgeRuntimeShared
// in processor_factory.go).
//
// Manager.Update() is invoked on SIGHUP from the fan-out goroutine — per-stream
// SIGHUP handlers rebuild only the pipeline, not the shared blocklist state.
// ChainChecker and WarningsWriter are nil when chain_guard.enabled == false —
// every caller MUST nil-check before use.
type SharedResources struct {
	BlocklistManager *blocklist.Manager
	ChainChecker     *chaincheck.Checker    // nil if chain_guard disabled
	WarningsWriter   *output.WarningsWriter // nil if chain_guard disabled
}
