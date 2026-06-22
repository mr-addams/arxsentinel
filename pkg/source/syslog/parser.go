// ========================== pkg/source/syslog — syslog envelope parser ==================
//   Strips RFC 3164 / RFC 5424 syslog envelope and returns the embedded log line.
//   Used by the syslog source plugin to extract raw access log entries from
//   syslog-forwarded messages (e.g. rsyslog → TCP/UDP).

package syslog

import (
	"bytes"
	"fmt"
)

// parseMessage strips the syslog envelope and returns the embedded log line.
// Supports RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
// Supports RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
// Auto-detects format: RFC 5424 has version field "1" immediately after the priority field.
// Returns error only if the <PRI> bracket is absent (malformed packet).
func parseMessage(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("syslog: empty message")
	}

	idx := bytes.IndexByte(raw, '>')
	if idx < 0 || idx > 6 {
		return "", fmt.Errorf("syslog: malformed message: missing or invalid priority bracket")
	}

	rest := raw[idx+1:]
	if len(rest) == 0 {
		return "", fmt.Errorf("syslog: empty message after priority")
	}

	if len(rest) > 1 && rest[0] == '1' && rest[1] == ' ' {
		return parseRFC5424(rest)
	}
	return parseRFC3164(rest)
}

// parseRFC3164 skips 5 space-separated fields after PRI:
// TIMESTAMP (3 parts: Mmm DD HH:MM:SS), HOSTNAME (1), TAG: (1, ends with colon).
func parseRFC3164(data []byte) (string, error) {
	fieldCount := 0
	i := 0

	for i < len(data) && fieldCount < 5 {
		// Skip leading spaces
		for i < len(data) && data[i] == ' ' {
			i++
		}
		if i >= len(data) {
			break
		}
		// Skip the field
		for i < len(data) && data[i] != ' ' {
			i++
		}
		fieldCount++
	}
	if fieldCount < 5 {
		return "", fmt.Errorf("syslog: RFC 3164 message too short")
	}

	// Skip trailing spaces to the message body
	for i < len(data) && data[i] == ' ' {
		i++
	}
	if i >= len(data) {
		return "", fmt.Errorf("syslog: RFC 3164 message has no content after header")
	}

	return string(data[i:]), nil
}

// parseRFC5424 skips 7 fields after PRI:
// VERSION, TIMESTAMP, HOST, APP, PROCID, MSGID,
// STRUCTURED-DATA (either "-" or "[...]" which may contain spaces).
func parseRFC5424(data []byte) (string, error) {
	fieldCount := 0
	i := 0

	for i < len(data) && fieldCount < 7 {
		// Skip leading spaces
		for i < len(data) && data[i] == ' ' {
			i++
		}
		if i >= len(data) {
			break
		}
		// Field 7 (STRUCTURED-DATA, 0-indexed as 6): may be "[...]" with spaces inside
		if fieldCount == 6 && data[i] == '[' {
			i++ // skip opening '['
			for i < len(data) && data[i] != ']' {
				i++
			}
			if i < len(data) {
				i++ // skip closing ']'
			}
		} else {
			// Ordinary field: skip until next space
			for i < len(data) && data[i] != ' ' {
				i++
			}
		}
		fieldCount++
	}
	if fieldCount < 7 {
		return "", fmt.Errorf("syslog: RFC 5424 message too short")
	}

	// Skip trailing spaces to the message body
	for i < len(data) && data[i] == ' ' {
		i++
	}
	if i >= len(data) {
		return "", fmt.Errorf("syslog: RFC 5424 message has no content after header")
	}

	return string(data[i:]), nil
}
