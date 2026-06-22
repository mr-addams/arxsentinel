// ========================== Module pkg/detector/params ==================================
//   Helper functions for extracting typed values from DetectorConfig.Params.
//
//   yaml.v3 parses map[string]interface{} values as Go native types:
//     integers  → int
//     floats    → float64
//     booleans  → bool
//     strings   → string
//     sequences → []interface{}
//   These helpers handle all realistic type variants so factories stay clean.
//
//   All helpers return the provided default when the key is absent or the type
//   cannot be converted — silent degradation keeps legacy configs working.

package detector

import (
	"time"
)

// GetInt extracts an int value from DetectorConfig.Params.
// Handles int, int64, and float64 (yaml sometimes produces float64 for whole numbers).
// Called from: each detector factory and external sub-packages. Non-blocking.
func GetInt(cfg DetectorConfig, key string, defaultVal int) int {
	m := cfg.Params
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	}
	return defaultVal
}

// getInt is a transition alias for GetInt using a params map directly.
// Deprecated: kept for compatibility with existing detector factories.
func getInt(m map[string]interface{}, key string, def int) int {
	return GetInt(DetectorConfig{Params: m}, key, def)
}

// GetFloat64 extracts a float64 value from DetectorConfig.Params.
// Handles float64 and integer types for YAML values like `0.6` or `1`.
// Called from: each detector factory and external sub-packages. Non-blocking.
func GetFloat64(cfg DetectorConfig, key string, defaultVal float64) float64 {
	m := cfg.Params
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	}
	return defaultVal
}

// getFloat64 is a transition alias for GetFloat64 using a params map directly.
// Deprecated: kept for compatibility with existing detector factories.
func getFloat64(m map[string]interface{}, key string, def float64) float64 {
	return GetFloat64(DetectorConfig{Params: m}, key, def)
}

// GetBool extracts a bool value from DetectorConfig.Params.
// Called from: each detector factory and external sub-packages. Non-blocking.
func GetBool(cfg DetectorConfig, key string, defaultVal bool) bool {
	m := cfg.Params
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return defaultVal
}

// getBool is a transition alias for GetBool using a params map directly.
// Deprecated: kept for compatibility with existing detector factories.
func getBool(m map[string]interface{}, key string, def bool) bool {
	return GetBool(DetectorConfig{Params: m}, key, def)
}

// GetDuration extracts a time.Duration from DetectorConfig.Params.
//
// Accepted forms:
//   - string: "30s", "1m", "500ms" — parsed via time.ParseDuration
//   - int / int64 / float64: nanoseconds — used directly as time.Duration
//
// Returns defaultVal on missing key, unknown type, or parse error.
// Called from: each detector factory and external sub-packages. Non-blocking.
func GetDuration(cfg DetectorConfig, key string, defaultVal time.Duration) time.Duration {
	m := cfg.Params
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	switch val := v.(type) {
	case string:
		dur, err := time.ParseDuration(val)
		if err != nil {
			return defaultVal
		}
		return dur
	case int:
		return time.Duration(val)
	case int64:
		return time.Duration(val)
	case float64:
		return time.Duration(int64(val))
	}
	return defaultVal
}

// getDuration is a transition alias for GetDuration using a params map directly.
// Deprecated: kept for compatibility with existing detector factories.
func getDuration(m map[string]interface{}, key string, def time.Duration) time.Duration {
	return GetDuration(DetectorConfig{Params: m}, key, def)
}

// GetStrings extracts a []string from DetectorConfig.Params.
//
// Accepted forms:
//   - []string: returned as-is
//   - []interface{}: each element cast to string; non-string items are skipped
//
// Returns defaultVal on missing key or wrong type.
// Called from: each detector factory and external sub-packages. Non-blocking.
func GetStrings(cfg DetectorConfig, key string, defaultVal []string) []string {
	m := cfg.Params
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		ss := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				ss = append(ss, s)
			}
		}
		return ss
	}
	return defaultVal
}

// getStrings is a transition alias for GetStrings using a params map directly.
// Deprecated: kept for compatibility with existing detector factories.
func getStrings(m map[string]interface{}, key string, def []string) []string {
	return GetStrings(DetectorConfig{Params: m}, key, def)
}
