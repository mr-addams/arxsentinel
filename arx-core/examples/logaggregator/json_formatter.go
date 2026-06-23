package main

import (
	"encoding/json"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/sink/format"
)

// JSONFormatter serializes a *plugin.Event whose Payload is *LogRecord into
// a single JSON object. It implements format.Formatter (the sink-agnostic
// serializer contract from arx-core/pkg/sink/format).
//
// The sink that calls us never inspects Payload — that is the canonical
// Gate B dissolution. The Formatter type-asserts to its own payload type
// and renders bytes; the sink only knows it got back a []byte.
type JSONFormatter struct{}

// Compile-time check that JSONFormatter satisfies format.Formatter.
var _ format.Formatter = (*JSONFormatter)(nil)

// outJSON is the wire shape: an envelope block (transport metadata owned
// by the runtime) plus a record block (product-owned payload).
// Field tags match the README example so newcomers can compare output
// against the documented shape.
type outJSON struct {
	Time       string `json:"time"`
	Host       string `json:"host"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	RemoteAddr string `json:"remote_addr"`
	Status     int    `json:"status"`
	Path       string `json:"path"`
	Stream     string `json:"stream"`
	Source     string `json:"source"`
	SourceType string `json:"source_type"`
	Level      string `json:"level"`
}

// Format implements format.Formatter. The sink calls this on every Write;
// we return bytes without a trailing newline (the file sink appends '\n').
func (j *JSONFormatter) Format(event *plugin.Event) ([]byte, error) {
	if event == nil {
		return nil, fmt.Errorf("json formatter: nil event")
	}
	rec, ok := event.Payload.(*LogRecord)
	if !ok {
		// The example's Formatter only knows *LogRecord. A sink fed a different
		// payload type indicates a pipeline misconfiguration; fail loudly so
		// the bug surfaces at the first observation, not silently at empty sinks.
		return nil, fmt.Errorf("json formatter: payload is %T, expected *LogRecord", event.Payload)
	}
	out := outJSON{
		Time:       rec.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		Host:       rec.Host,
		Severity:   rec.Severity,
		Message:    rec.Message,
		RemoteAddr: rec.RemoteAddr,
		Status:     rec.Status,
		Path:       rec.Path,
		Stream:     event.Envelope.Stream,
		Source:     event.Envelope.Source,
		SourceType: event.Envelope.SourceType,
		Level:      event.Envelope.Level,
	}
	return json.Marshal(out)
}