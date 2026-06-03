package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
)

type EnvelopeRecord struct {
	RawLine   string
	Timestamp int64
	Metadata  map[string]string
}

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