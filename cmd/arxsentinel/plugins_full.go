//go:build !arx_tag

// ========================== Plugin blank-imports — full profile ==========================
//   Side-effect registration of all 12 blank-import transports for the default (full)
//   build. Excluded when the sentinel `arx_tag` build tag is set, in which case
//   generated `plugins_<profile>.go` files (under `//go:build arx_tag && <profile>`)
//   provide a profile-specific subset instead.
//
//   WHAT IS HERE:
//     - 14 blank imports matching profiles/full.yaml (Decision 11, Flow 075).
//     - Order is alphabetical by import path for deterministic diff.
//
//   WHAT IS NOT HERE:
//     - pkg/detector — named-import in validate.go/builders.go (always-linked, Decision 12).
//     - pkg/sink/file — named-import in pipeline.go (always-linked, not a profile transport).
//
//   See: docs/architecture/adr/003-build-modularity.md, ADR-002 (module mapping).

package main

import (
	_ "github.com/mr-addams/arxsentinel/pkg/executorplugins/cloudflare"
	_ "github.com/mr-addams/arxsentinel/pkg/executorplugins/mikrotik"
	_ "github.com/mr-addams/arxsentinel/pkg/executorplugins/nginx"
	_ "github.com/mr-addams/arxsentinel/pkg/processorplugins/chaincheck"
	_ "github.com/mr-addams/arxsentinel/pkg/processorplugins/whitelist"

	// Plugin detectors (tree-shakeable side-effect registration, Flow 076)
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/badbot"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/bruteforce"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/crawler"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/noasset"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/overflow"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/probe"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/rate"
	_ "github.com/mr-addams/arxsentinel/pkg/detectorplugins/useragent" // registry name: "ua"

	_ "github.com/mr-addams/arx-core/pkg/sink/exec"
	_ "github.com/mr-addams/arx-core/pkg/sink/sentinel"
	_ "github.com/mr-addams/arx-core/pkg/sink/stdout"
	_ "github.com/mr-addams/arx-core/pkg/source/exec"
	_ "github.com/mr-addams/arx-core/pkg/source/file"
	_ "github.com/mr-addams/arx-core/pkg/source/http"
	_ "github.com/mr-addams/arx-core/pkg/source/sentinel"
	_ "github.com/mr-addams/arx-core/pkg/source/stdin"
	_ "github.com/mr-addams/arx-core/pkg/source/syslog"
)
