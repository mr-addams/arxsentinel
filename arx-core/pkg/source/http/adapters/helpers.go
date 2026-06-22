// ====== Module: Adapter Helpers ======
// Shared utilities for adapters: timestamp normalization and map copying.

package adapters

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// normalizeTimestamp converts various timestamp formats to Unix nanoseconds.
// Supports: unix_ns, unix_ns_str, unix_ms, rfc3339, unix_float.
// Returns error if format is unknown or value is out of range.
// Called from: adapter Decode() methods to normalize vendor timestamps.
func normalizeTimestamp(val string, kind string) (int64, error) {
	switch kind {
	case "unix_ns":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid unix_ns value %q: %w", val, err)
		}
		return n, nil
	case "unix_ns_str":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid unix_ns_str value %q: %w", val, err)
		}
		return n, nil
	case "unix_ms":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid unix_ms value %q: %w", val, err)
		}
		return n * 1_000_000, nil
	case "rfc3339":
		t, err := time.Parse(time.RFC3339, val)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid rfc3339 value %q: %w", val, err)
		}
		return t.UnixNano(), nil
	case "unix_float":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid unix_float value %q: %w", val, err)
		}
		const maxUnixFloatSec = float64(math.MaxInt64) / 1e9
		const minUnixFloatSec = float64(math.MinInt64) / 1e9
		if f > maxUnixFloatSec || f < minUnixFloatSec {
			return 0, fmt.Errorf("unix_float timestamp %v out of range", f)
		}
		return int64(f * 1e9), nil
	default:
		return 0, fmt.Errorf("normalize timestamp: unknown kind %q", kind)
	}
}

// copyMap creates a shallow copy of a string map.
// Returns nil if input is nil. Used to safely copy metadata.
// Non-blocking. Called from: adapter WriteAck() methods for meta manipulation.
func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
