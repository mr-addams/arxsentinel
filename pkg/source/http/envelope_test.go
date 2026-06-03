package http

import (
	"bytes"
	"compress/gzip"
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