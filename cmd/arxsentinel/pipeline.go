// ========================== Shared resources — product-side singleton container ============
//   Этот файл хранит ТОЛЬКО singleton-контейнер, разделяемый между product-обработчиком
//   (cmd/arxsentinel/processor_security.go), его сборщиком (processor_factory.go),
//   и detector-фабриками (builders.go).
//
//   ЧТО ЗДЕСЬ:
//     - SharedResources          — product-side singleton-контейнер (blocklist,
//                                  chain-check, warnings writer); конвертируется в
//                                  runtime.SharedResources в main.go через
//                                  bridgeRuntimeShared (processor_factory.go).
//
//   ИСТОРИЯ: до Phase 3 Flow 081 здесь же жили runStream / runPipeline / processLine
//   и тип PipelineContext. После выделения runtime-движка в arx-core/pkg/runtime
//   эти функции и тип удалены; на их месте остался только DTO SharedResources.

package main

import (
	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/internal/core/output"
)

// SharedResources хранит singleton-зависимости, общие для всех стримов.
// Создаётся один раз в main() до запуска стримов; передаётся в securityFactory
// через runtime.SharedResources (см. bridgeRuntimeShared в processor_factory.go).
//
// Manager.Update() вызывается при SIGHUP из fan-out-горутины — per-stream
// SIGHUP-хендлеры перестраивают только pipeline, не общий blocklist-state.
// ChainChecker и WarningsWriter — nil при chain_guard.enabled == false —
// все вызывающие обязаны делать nil-check перед использованием.
type SharedResources struct {
	BlocklistManager *blocklist.Manager
	ChainChecker     *chaincheck.Checker    // nil if chain_guard disabled
	WarningsWriter   *output.WarningsWriter // nil if chain_guard disabled
}
