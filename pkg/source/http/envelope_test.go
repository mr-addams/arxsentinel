package http

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMaybeGunzip(t *testing.T) {
	tests := []struct {
		name            string
		input           []byte
		contentEncoding string
		maxBytes        int64
		want            string
		wantErr         bool
	}{
		{
			name:            "valid gzip",
			contentEncoding: "gzip",
			maxBytes:        1024 * 1024,
			want:            "hello world",
		},
		{
			name:            "plain identity",
			input:           []byte("hello world"),
			contentEncoding: "identity",
			maxBytes:        1024 * 1024,
			want:            "hello world",
		},
		{
			name:            "empty string encoding",
			input:           []byte("hello world"),
			contentEncoding: "",
			maxBytes:        1024 * 1024,
			want:            "hello world",
		},
		{
			name:            "unsupported encoding br",
			input:           []byte("hello world"),
			contentEncoding: "br",
			maxBytes:        1024 * 1024,
			wantErr:         true,
		},
		{
			name:            "truncated gzip",
			input:           []byte{0x1f, 0x8b, 0x08, 0x00},
			contentEncoding: "gzip",
			maxBytes:        1024 * 1024,
			wantErr:         true,
		},
		{
			name:            "gzip bomb: decompressed exceeds maxBytes",
			contentEncoding: "gzip",
			maxBytes:        10 * 1024 * 1024,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			switch tt.name {
			case "valid gzip":
				input = makeGzip(t, []byte("hello world"))
			case "gzip bomb: decompressed exceeds maxBytes":
				input = makeGzip(t, bytes.Repeat([]byte("x"), 11*1024*1024))
			}

			got, err := maybeGunzip(input, tt.contentEncoding, tt.maxBytes)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestReadLimited(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		maxBytes int64
		want     string
		wantErr  bool
	}{
		{
			name:     "body under limit",
			body:     "hello",
			maxBytes: 10,
			want:     "hello",
		},
		{
			name:     "body exactly at limit",
			body:     "hello",
			maxBytes: 5,
			want:     "hello",
		},
		{
			name:     "body over limit by 1 byte",
			body:     "hello",
			maxBytes: 4,
			wantErr:  true,
		},
		{
			name:     "empty body",
			body:     "",
			maxBytes: 10,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readLimited(strings.NewReader(tt.body), tt.maxBytes)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func makeGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func TestNormalizeTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		kind    string
		want    int64
		wantErr bool
	}{
		{
			name: "unix_ns",
			val:  "1000000000",
			kind: "unix_ns",
			want: 1000000000,
		},
		{
			name: "unix_ms",
			val:  "1000",
			kind: "unix_ms",
			want: 1000000000,
		},
		{
			name: "rfc3339",
			val:  "1970-01-01T00:00:01Z",
			kind: "rfc3339",
			want: 1000000000,
		},
		{
			name: "unix_float",
			val:  "1.5",
			kind: "unix_float",
			want: 1500000000,
		},
		{
			name: "unix_ns_str",
			val:  "1000000000",
			kind: "unix_ns_str",
			want: 1000000000,
		},
		{
			name:    "unknown kind",
			val:     "1000",
			kind:    "unknown",
			wantErr: true,
		},
		{
			name:    "invalid value for unix_ns",
			val:     "not-a-number",
			kind:    "unix_ns",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTimestamp(tt.val, tt.kind)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDecodePlain(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want int
	}{
		{name: "empty body", body: []byte(""), want: 0},
		{name: "single line, no newline", body: []byte("hello"), want: 1},
		{name: "three lines with LF", body: []byte("a\nb\nc"), want: 3},
		{name: "CRLF line endings", body: []byte("a\r\nb\r\nc"), want: 3},
		{name: "blank lines between content", body: []byte("a\n\nb\n\nc"), want: 3},
		{name: "large body 100 lines", body: []byte(strings.Repeat("x\n", 100)), want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodePlain(tt.body)
			if len(got) != tt.want {
				t.Errorf("got %d lines, want %d", len(got), tt.want)
			}
			for _, line := range got {
				if strings.Contains(line, "\r") {
					t.Errorf("line contains CR: %q", line)
				}
			}
		})
	}
}

func TestDecodeNDJSON(t *testing.T) {
	t.Run("valid ndjson with field", func(t *testing.T) {
		body := []byte(`{"msg":"hello"}
{"msg":"world"}`)
		got, err := decodeNDJSON(body, "msg")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "hello" || got[1] != "world" {
			t.Fatalf("got %v, want [hello world]", got)
		}
	})

	t.Run("valid ndjson, empty field", func(t *testing.T) {
		body := []byte(`{"a":1}
{"b":2}`)
		got, err := decodeNDJSON(body, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d lines, want 2", len(got))
		}
	})

	t.Run("missing field", func(t *testing.T) {
		body := []byte(`{"x":"y"}`)
		_, err := decodeNDJSON(body, "nonexistent")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Errorf("error should mention field name: %v", err)
		}
	})

	t.Run("malformed JSON line", func(t *testing.T) {
		body := []byte(`{invalid}`)
		_, err := decodeNDJSON(body, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("field value is a JSON object", func(t *testing.T) {
		body := []byte(`{"data":{"nested":"val"}}`)
		got, err := decodeNDJSON(body, "data")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != `{"nested":"val"}` {
			t.Fatalf("got %v, want [{\"nested\":\"val\"}]", got)
		}
	})
}

func TestBase64Decode(t *testing.T) {
	t.Run("valid base64 string", func(t *testing.T) {
		got, err := base64Decode(base64.StdEncoding.EncodeToString([]byte("hello")))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello" {
			t.Errorf("got %q, want %q", string(got), "hello")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := base64Decode("!!!not-base64!!!")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		got, err := base64Decode("")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("got %d bytes, want 0", len(got))
		}
	})
}

func TestExtractJSONField(t *testing.T) {
	t.Run("top-level field", func(t *testing.T) {
		body := []byte(`{"key":"val"}`)
		got, err := extractJSONField(body, "key")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"val"` {
			t.Errorf("got %q, want %q", string(got), `"val"`)
		}
	})

	t.Run("nested path", func(t *testing.T) {
		body := []byte(`{"a":{"b":"deep"}}`)
		got, err := extractJSONField(body, "a.b")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"deep"` {
			t.Errorf("got %q, want %q", string(got), `"deep"`)
		}
	})

	t.Run("missing top-level field", func(t *testing.T) {
		body := []byte(`{"a":1}`)
		_, err := extractJSONField(body, "b")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing nested field", func(t *testing.T) {
		body := []byte(`{"a":{"b":"deep"}}`)
		_, err := extractJSONField(body, "a.c")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("non-object at intermediate path", func(t *testing.T) {
		body := []byte(`{"a":"string"}`)
		_, err := extractJSONField(body, "a.b")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("three-level path", func(t *testing.T) {
		body := []byte(`{"a":{"b":{"c":"deep3"}}}`)
		got, err := extractJSONField(body, "a.b.c")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"deep3"` {
			t.Errorf("got %q, want %q", string(got), `"deep3"`)
		}
	})
}
