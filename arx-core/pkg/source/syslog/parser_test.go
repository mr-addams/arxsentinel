// ========================== pkg/source/syslog — parser tests ================================
//   Tests: RFC3164, RFC5424 (nil SD + with SD), MissingPRI, EmptyInput, Short messages.

package syslog

import (
	"testing"
)

func TestParseMessage_RFC3164(t *testing.T) {
	input := `<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	expected := `1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`

	line, err := parseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != expected {
		t.Fatalf("got:  %q\nwant: %q", line, expected)
	}
}

func TestParseMessage_RFC5424_NilSD(t *testing.T) {
	input := `<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - - 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`
	expected := `1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"`

	line, err := parseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != expected {
		t.Fatalf("got:  %q\nwant: %q", line, expected)
	}
}

func TestParseMessage_MissingPRI(t *testing.T) {
	input := `no priority bracket here`

	_, err := parseMessage([]byte(input))
	if err == nil {
		t.Fatal("expected error for missing priority bracket")
	}
}

func TestParseMessage_EmptyInput(t *testing.T) {
	_, err := parseMessage([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseMessage_Short3164(t *testing.T) {
	input := `<134>Jun  3 12:00:00`

	_, err := parseMessage([]byte(input))
	if err == nil {
		t.Fatal("expected error for short RFC 3164 message")
	}
}

func TestParseMessage_Short5424(t *testing.T) {
	input := `<134>1 2026-06-03T12:00:00Z myhost`

	_, err := parseMessage([]byte(input))
	if err == nil {
		t.Fatal("expected error for short RFC 5424 message")
	}
}

func TestParseMessage_RFC5424_WithSD(t *testing.T) {
	input := `<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - [example@32473 iut="3" eventSource="Application"] 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612`
	expected := `1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612`

	line, err := parseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != expected {
		t.Fatalf("got:  %q\nwant: %q", line, expected)
	}
}
