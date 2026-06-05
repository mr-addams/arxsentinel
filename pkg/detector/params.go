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

// getInt extracts an int value from a params map.
// Handles int, int64, and float64 (yaml sometimes produces float64 for whole numbers).
// Called from: each detector factory. Non-blocking.
func getInt(m map[string]interface{}, key string, def int) int {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	}
	return def
}

// getFloat64 extracts a float64 value from a params map.
// Handles float64 and integer types for YAML values like `0.6` or `1`.
// Called from: each detector factory. Non-blocking.
func getFloat64(m map[string]interface{}, key string, def float64) float64 {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	}
	return def
}

// getBool extracts a bool value from a params map.
// Called from: each detector factory. Non-blocking.
func getBool(m map[string]interface{}, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

// getDuration extracts a time.Duration from a params map.
//
// Accepted forms:
//   - string: "30s", "1m", "500ms" — parsed via time.ParseDuration
//   - int / int64 / float64: nanoseconds — used directly as time.Duration
//
// Returns def on missing key, unknown type, or parse error.
// Called from: each detector factory. Non-blocking.
func getDuration(m map[string]interface{}, key string, def time.Duration) time.Duration {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch val := v.(type) {
	case string:
		dur, err := time.ParseDuration(val)
		if err != nil {
			return def
		}
		return dur
	case int:
		return time.Duration(val)
	case int64:
		return time.Duration(val)
	case float64:
		return time.Duration(int64(val))
	}
	return def
}

// getStrings extracts a []string from a params map.
//
// Accepted forms:
//   - []string: returned as-is
//   - []interface{}: each element cast to string; non-string items are skipped
//
// Returns def on missing key or wrong type.
// Called from: each detector factory. Non-blocking.
func getStrings(m map[string]interface{}, key string, def []string) []string {
	v, ok := m[key]
	if !ok {
		return def
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
	return def
}

// noopMatcher is a Matcher that never matches.
// Used when SharedResources is nil or returns a nil Blocklist —
// the detector remains functional but cannot match any blocklist entry.
type noopMatcher struct{}

func (noopMatcher) Match(string, string) bool { return false }

func (noopMatcher) MatchResult(string, string) (string, bool) { return "", false }

