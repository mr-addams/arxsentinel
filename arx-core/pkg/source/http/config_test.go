package http

import (
	"testing"
	"time"

	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

func TestParseHTTPConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     pkgsource.InputConfig
		want    *parsedConfig
		wantErr bool
	}{
		{
			name: "push plain HTTP",
			cfg: pkgsource.InputConfig{
				Addr:     "http://0.0.0.0:8080",
				Protocol: "plain",
			},
			want: &parsedConfig{
				mode:         "push",
				scheme:       "http",
				host:         "0.0.0.0",
				port:         "8080",
				path:         "/",
				proto:        "plain",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "push HTTPS",
			cfg: pkgsource.InputConfig{
				Addr:     "https://0.0.0.0:443",
				Protocol: "plain",
				TLSCert:  "c",
				TLSKey:   "k",
			},
			want: &parsedConfig{
				mode:         "push",
				scheme:       "https",
				host:         "0.0.0.0",
				port:         "443",
				path:         "/",
				proto:        "plain",
				tlsCert:      "c",
				tlsKey:       "k",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "push with path",
			cfg: pkgsource.InputConfig{
				Addr:     "http://0.0.0.0:8080/ingest",
				Protocol: "plain",
			},
			want: &parsedConfig{
				mode:         "push",
				scheme:       "http",
				host:         "0.0.0.0",
				port:         "8080",
				path:         "/ingest",
				proto:        "plain",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "pull plain",
			cfg: pkgsource.InputConfig{
				Mode:         "pull",
				URL:          "http://remote:9000/logs",
				Protocol:     "plain",
				PullInterval: "60s",
			},
			want: &parsedConfig{
				mode:         "pull",
				scheme:       "http",
				host:         "remote",
				port:         "9000",
				path:         "/logs",
				proto:        "plain",
				pullInterval: 60 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "push no protocol",
			cfg: pkgsource.InputConfig{
				Addr: "http://0.0.0.0:8080",
			},
			wantErr: true,
		},
		{
			name: "push HTTPS no cert",
			cfg: pkgsource.InputConfig{
				Addr:     "https://0.0.0.0:443",
				Protocol: "plain",
			},
			wantErr: true,
		},
		{
			name: "pull no url",
			cfg: pkgsource.InputConfig{
				Mode:     "pull",
				Protocol: "plain",
			},
			wantErr: true,
		},
		{
			name: "unknown protocol",
			cfg: pkgsource.InputConfig{
				Addr:     "http://0.0.0.0:8080",
				Protocol: "unknown",
			},
			wantErr: true,
		},
		{
			name: "default path",
			cfg: pkgsource.InputConfig{
				Addr:     "http://0.0.0.0:8080",
				Protocol: "plain",
			},
			want: &parsedConfig{
				mode:         "push",
				scheme:       "http",
				host:         "0.0.0.0",
				port:         "8080",
				path:         "/",
				proto:        "plain",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "default maxBodyBytes",
			cfg: pkgsource.InputConfig{
				Addr:     "http://0.0.0.0:8080",
				Protocol: "plain",
			},
			want: &parsedConfig{
				mode:         "push",
				scheme:       "http",
				host:         "0.0.0.0",
				port:         "8080",
				path:         "/",
				proto:        "plain",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
		{
			name: "default pullInterval",
			cfg: pkgsource.InputConfig{
				Mode:     "pull",
				URL:      "http://remote:9000/logs",
				Protocol: "plain",
			},
			want: &parsedConfig{
				mode:         "pull",
				scheme:       "http",
				host:         "remote",
				port:         "9000",
				path:         "/logs",
				proto:        "plain",
				pullInterval: 30 * time.Second,
				maxBodyBytes: 10 * 1024 * 1024,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHTTPConfig(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.mode != tt.want.mode {
				t.Errorf("mode = %q, want %q", got.mode, tt.want.mode)
			}
			if got.scheme != tt.want.scheme {
				t.Errorf("scheme = %q, want %q", got.scheme, tt.want.scheme)
			}
			if got.host != tt.want.host {
				t.Errorf("host = %q, want %q", got.host, tt.want.host)
			}
			if got.port != tt.want.port {
				t.Errorf("port = %q, want %q", got.port, tt.want.port)
			}
			if got.path != tt.want.path {
				t.Errorf("path = %q, want %q", got.path, tt.want.path)
			}
			if got.proto != tt.want.proto {
				t.Errorf("proto = %q, want %q", got.proto, tt.want.proto)
			}
			if got.token != tt.want.token {
				t.Errorf("token = %q, want %q", got.token, tt.want.token)
			}
			if got.envelopeField != tt.want.envelopeField {
				t.Errorf("envelopeField = %q, want %q", got.envelopeField, tt.want.envelopeField)
			}
			if got.tlsCert != tt.want.tlsCert {
				t.Errorf("tlsCert = %q, want %q", got.tlsCert, tt.want.tlsCert)
			}
			if got.tlsKey != tt.want.tlsKey {
				t.Errorf("tlsKey = %q, want %q", got.tlsKey, tt.want.tlsKey)
			}
			if got.pullInterval != tt.want.pullInterval {
				t.Errorf("pullInterval = %v, want %v", got.pullInterval, tt.want.pullInterval)
			}
			if got.maxBodyBytes != tt.want.maxBodyBytes {
				t.Errorf("maxBodyBytes = %d, want %d", got.maxBodyBytes, tt.want.maxBodyBytes)
			}
		})
	}
}
