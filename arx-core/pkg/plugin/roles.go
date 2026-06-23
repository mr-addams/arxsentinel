// ========================== pkg/plugin — role constants ===================================
//   Role identifies a plugin's position and responsibility in the pipeline.
//   Used by the manifest system to validate topology (e.g. no two Sources of the same name)
//   and to route lifecycle events (e.g. only Sources receive start/stop).

package plugin

// Role identifies a plugin's position and responsibility in the pipeline.
type Role string

const (
	// RoleSource is the first stage — reads raw data from an external source.
	RoleSource Role = "source"
	// RoleProcessor transforms or enriches data before detection.
	RoleProcessor Role = "processor"
	// RoleDetector analyses data for known attack or abuse patterns.
	RoleDetector Role = "detector"
	// RoleExecutor runs an action based on a detection result.
	RoleExecutor Role = "executor"
	// RoleSink is the terminal stage — persists results to storage.
	RoleSink Role = "sink"
)
