//go:build !arx_tag

// ========================== Plugin blank-imports — full profile ==========================
//   Side-effect registration of all 12 blank-import transports for the default (full)
//   build. Excluded when the sentinel `arx_tag` build tag is set, in which case
//   generated `plugins_<profile>.go` files (under `//go:build arx_tag && <profile>`)
//   provide a profile-specific subset instead.
//
//   WHAT IS HERE:
//     - 12 blank imports matching profiles/full.yaml (Decision 11, Flow 075).
//     - Order is alphabetical by import path for deterministic diff.
//
//   WHAT IS NOT HERE:
//     - pkg/executor/cloudflare — named-import in cleanup.go (always-linked, Decision 13).
//     - pkg/detector — named-import in validate.go/builders.go (always-linked, Decision 12).
//     - pkg/sink/file — named-import in pipeline.go (always-linked, not a profile transport).
//     - pkg/processor/{chaincheck,whitelist} — not imported anywhere (Decision 14, known issue).
//
//   See: docs/architecture/adr/003-build-modularity.md, ADR-002 (module mapping).

package main

import (
	_ "github.com/mr-addams/arxsentinel/pkg/executor/mikrotik"
	_ "github.com/mr-addams/arxsentinel/pkg/executor/nginx"
	_ "github.com/mr-addams/arxsentinel/pkg/processor"

	// Plugin detectors (tree-shakeable side-effect registration, Flow 076)
	_ "github.com/mr-addams/arxsentinel/pkg/detector/bruteforce"
	_ "github.com/mr-addams/arxsentinel/pkg/detector/noasset"
	_ "github.com/mr-addams/arxsentinel/pkg/detector/overflow"
	_ "github.com/mr-addams/arxsentinel/pkg/detector/probe"
	_ "github.com/mr-addams/arxsentinel/pkg/detector/rate"

	_ "github.com/mr-addams/arxsentinel/pkg/sink/exec"
	_ "github.com/mr-addams/arxsentinel/pkg/sink/sentinel"
	_ "github.com/mr-addams/arxsentinel/pkg/sink/stdout"
	_ "github.com/mr-addams/arxsentinel/pkg/source/exec"
	_ "github.com/mr-addams/arxsentinel/pkg/source/file"
	_ "github.com/mr-addams/arxsentinel/pkg/source/http"
	_ "github.com/mr-addams/arxsentinel/pkg/source/sentinel"
	_ "github.com/mr-addams/arxsentinel/pkg/source/stdin"
	_ "github.com/mr-addams/arxsentinel/pkg/source/syslog"
)