// ========================== Module pkg/pluginregistry ====================================
//   Generic plugin-registry core used by the five concrete plugin registries
//   (source, sink, executor, detector, processor) on feat/telemetrycore.
//
//   WHAT IS HERE:
//     Registry[F, M] — type-parameterised store keyed by plugin name. F is the
//                     opaque factory type the host registry registers;
//                     M is the opaque manifest type it stores alongside.
//                     The core NEVER calls F and NEVER inspects M — it only
//                     stores and returns them.
//
//   WHAT IS NOT HERE:
//     Build logic, dependency injection, context handling, nil-on-disabled,
//     execplugin fallback, error formatting, lifecycle. All of that lives in
//     the thin host wrappers (pkg/source, pkg/sink, pkg/executor,
//     pkg/detector, pkg/processor) — see Flow 070 / Phase 1.1.
//
//   DEPENDENCY RULE (ADR-002 boundary):
//     This package is a Core package. It imports ONLY the Go standard library.
//     Zero imports of internal/. Zero imports of pkg/plugin, pkg/execplugin,
//     or any product-domain package. Zero security-domain vocabulary
//     (no "threat"/"ban"/"bot"/...).
//
//   CONCURRENCY MODEL:
//     RWMutex guards both stores. Reads (Get, Names, ManifestByName) take a
//     read lock and are safe to call concurrently. Writes (Register,
//     RegisterManifest) take a write lock. Duplicate registration is a
//     programmer error and panics — same contract as the host registries.
//
//   WHY TWO TYPE PARAMETERS:
//     Hosts that carry manifests (source, sink, executor) parameterise
//     M = plugin.Manifest. Hosts without manifests (detector, processor)
//     parameterise M = struct{}. Both cases use the same core, so the
//     generic surface is uniform across the five registries — Success
//     Criterion #4 of Flow 070.

package pluginregistry
