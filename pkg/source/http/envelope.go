// ====== Module: HTTP Envelope Utilities ======
// Shared utilities for HTTP log processing: timestamp normalization, decompression,
// body reading with limits, NDJSON parsing, and JSON field extraction.

package http

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// normalizeTimestamp converts various timestamp formats to Unix nanoseconds.
// Supports: unix_ns, unix_ns_str, unix_ms, rfc3339, unix_float.
// Returns error if format is unknown or value is out of range.
// Called from: various adapter Decode() methods to normalize timestamps.
func normalizeTimestamp(val string, kind string) (int64, error) {
	switch kind {
	case "unix_ns", "unix_ns_str":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("normalize timestamp: invalid unix_ns value %q: %w", val, err)
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

// maybeGunzip decompresses gzip-encoded body if Content-Encoding matches.
// Returns original body if encoding is empty or "identity".
// Returns error if decompressed size exceeds maxBytes (prevents zip bombs).
// Called from: buildPushHandler() and runPull() to decompress request/response bodies.
func maybeGunzip(body []byte, contentEncoding string, maxBytes int64) ([]byte, error) {
	if contentEncoding == "" || contentEncoding == "identity" {
		return body, nil
	}
	if contentEncoding == "gzip" || contentEncoding == "x-gzip" {
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gunzip: %w", err)
		}
		defer r.Close()
		// читаем на 1 байт больше maxBytes, чтобы детектировать превышение лимита
		limited := io.LimitReader(r, maxBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("maybeGunzip: decompress: %w", err)
		}
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf("decompressed body exceeds %d bytes", maxBytes)
		}
		return data, nil
	}
	return nil, fmt.Errorf("unsupported Content-Encoding: %q", contentEncoding)
}

// readLimited reads up to maxBytes from reader, returns error if limit exceeded.
// Prevents memory exhaustion from oversized request bodies.
// Called from: buildPushHandler() and runPull() to read HTTP request/response bodies.
func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read limited: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxBytes)
	}
	return data, nil
}

// decodePlain splits body into lines, trims trailing \r, and returns non-empty lines.
// Used by generic adapter for plain newline-delimited logs. Non-blocking.
func decodePlain(body []byte) []string {
	lines := strings.Split(string(body), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// decodeNDJSON splits body into lines, parses each as JSON, and extracts the given field.
// If field is empty, the raw JSON object is used as the line string.
// If field is non-empty and missing in a line, decodeNDJSON returns an error immediately —
// this is intentional fail-fast behavior: a missing configured field indicates misconfiguration.
// Blank lines are silently skipped. Malformed JSON lines return an error.
func decodeNDJSON(body []byte, field string) ([]string, error) {
	lines := strings.Split(string(body), "\n")
	var result []string
	for lineIdx, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("ndjson line %d: %w", lineIdx, err)
		}
		if field != "" {
			val, ok := raw[field]
			if !ok {
				excerpt := line
				if len(excerpt) > 80 {
					excerpt = excerpt[:80] + "..."
				}
				return nil, fmt.Errorf("ndjson line %d: field %q not found in: %s", lineIdx, field, excerpt)
			}
			var s string
			if err := json.Unmarshal(val, &s); err != nil {
				result = append(result, string(val))
			} else {
				result = append(result, s)
			}
		} else {
			result = append(result, line)
		}
	}
	return result, nil
}

// base64Decode decodes base64-encoded string to bytes.
// Called from: adapters that receive base64-encoded log data (e.g., Cloudflare).
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// extractJSONField traverses body (JSON object) using a dot-separated path and returns
// the raw JSON bytes at that path. Returns an error if any path segment is missing or
// the intermediate value is not a JSON object. The returned bytes are raw JSON (may be
// string, number, object, or array — caller must unmarshal as needed).
func extractJSONField(body []byte, path string) ([]byte, error) {
	keys := strings.Split(path, ".")
	current := body
	for _, key := range keys {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(current, &obj); err != nil {
			excerpt := string(current)
			if len(excerpt) > 40 {
				excerpt = excerpt[:40] + "..."
			}
			return nil, fmt.Errorf("extractJSONField %q: key %q is not an object (got: %s)", path, key, excerpt)
		}
		val, ok := obj[key]
		if !ok {
			return nil, fmt.Errorf("field %q not found in JSON", path)
		}
		current = []byte(val)
	}
	return current, nil
}
