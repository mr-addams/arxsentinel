// ========================== pkg/execplugin — protocol messages =============================
//   Wire representation of plugin.LogEntry, plugin.ThreatEvent, and plugin.IPView
//   for NDJSON transport between arxsentinel and external plugin processes.
//
//   WHAT IS HERE:
//     - Protocol message types (Detect, Write, Source, Start/Stop control)
//     - LogEntryJSON, ThreatEventJSON, IPViewJSON — wire-safe flat structs
//     - Helper functions to convert between plugin and JSON types
//
//   WHAT IS NOT HERE:
//     - ManagedProcess (process.go)
//     - Detector/Sink/Source plugin implementations
//
//   WIRE FORMAT:
//     Each message is a single-line JSON followed by \n.
//     All timestamps use RFC3339 format.
//     All action fields are lowercase strings.

package execplugin

import (
	"encoding/json"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ProtoVersion is the protocol version number. Used for future compatibility checks.
const ProtoVersion = "1"

// LogEntryJSON is the wire representation of plugin.LogEntry for JSON transport.
// Flat struct mirrors plugin.LogEntry field-by-field to avoid requiring
// external plugin authors to import internal packages.
// Consumer: protocol.go (DetectRequest.entry), source.go (SourceEntry.entry).
type LogEntryJSON struct {
	RemoteAddr string `json:"remote_addr"` // YAML: — parsed from log line. Consumer: protocol.logEntryToJSON
	RemoteUser string `json:"remote_user"` // YAML: — parsed from log line. Consumer: protocol.logEntryToJSON
	Time       string `json:"time"`        // YAML: — RFC3339 parsed timestamp. Consumer: protocol.logEntryToJSON
	Method     string `json:"method"`      // YAML: — HTTP method (GET, POST, etc.). Consumer: protocol.logEntryToJSON
	RawURI     string `json:"raw_uri"`     // YAML: — full URI before parsing. Consumer: protocol.logEntryToJSON
	Path       string `json:"path"`        // YAML: — URL path component. Consumer: protocol.logEntryToJSON
	Query      string `json:"query"`       // YAML: — URL query string. Consumer: protocol.logEntryToJSON
	Protocol   string `json:"protocol"`    // YAML: — HTTP protocol version. Consumer: protocol.logEntryToJSON
	Status     int    `json:"status"`      // YAML: — HTTP response status code. Consumer: protocol.logEntryToJSON
	BytesSent  int64  `json:"bytes_sent"`  // YAML: — bytes sent to client. Consumer: protocol.logEntryToJSON
	Referer    string `json:"referer"`     // YAML: — HTTP Referer header. Consumer: protocol.logEntryToJSON
	UserAgent  string `json:"user_agent"`  // YAML: — User-Agent header. Consumer: protocol.logEntryToJSON
	RealIP     string `json:"real_ip"`     // YAML: — real client IP from X-Forwarded-For. Consumer: protocol.logEntryToJSON
}

// IPViewJSON is the wire representation of plugin.IPView for JSON transport.
// Captures a point-in-time snapshot of per-IP state.
// Consumer: protocol.go (DetectRequest.state).
type IPViewJSON struct {
	IP            string   `json:"ip"`             // YAML: — client IP address. Consumer: protocol.ipViewToJSON
	TotalRequests int      `json:"total_requests"` // YAML: — cumulative request count. Consumer: protocol.ipViewToJSON
	Requests404   int      `json:"requests_404"`   // YAML: — count of 404 responses. Consumer: protocol.ipViewToJSON
	RecentPaths   []string `json:"recent_paths"`   // YAML: — last N request paths (scored). Consumer: protocol.ipViewToJSON
	ApproxRate    float64  `json:"approx_rate_1m"` // YAML: — requests/second over 1 minute window. Consumer: protocol.ipViewToJSON
}

// ThreatEventJSON is the wire representation of plugin.ThreatEvent for JSON transport.
// Includes all fields needed to route the event to external systems.
// Consumer: protocol.go (WriteRequest.event, ExecuteRequest.event).
type ThreatEventJSON struct {
	Timestamp  string   `json:"timestamp"`          // YAML: — RFC3339 event timestamp. Consumer: protocol.threatEventToJSON
	Level      string   `json:"level"`              // YAML: — threat level (WARN/THREAT). Consumer: protocol.threatEventToJSON
	Stream     string   `json:"stream"`             // YAML: — stream name. Consumer: protocol.threatEventToJSON
	Source     string   `json:"source"`             // YAML: — source path. Consumer: protocol.threatEventToJSON
	SourceType string   `json:"source_type"`        // YAML: — source type (file, etc.). Consumer: protocol.threatEventToJSON
	IP         string   `json:"ip"`                 // YAML: — client IP address. Consumer: protocol.threatEventToJSON
	Score      int      `json:"score"`              // YAML: — accumulated threat score. Consumer: protocol.threatEventToJSON
	Modules    []string `json:"modules"`            // YAML: — triggered detector names. Consumer: protocol.threatEventToJSON
	Reason     string   `json:"reason"`             // YAML: — human-readable reason. Consumer: protocol.threatEventToJSON
	RawLine    string   `json:"raw_line,omitempty"` // YAML: — original log line (omit if empty). Consumer: protocol.threatEventToJSON
}

// DetectRequest is sent to a detector plugin stdin.
// The plugin should read this, run detection logic, and return DetectResponse.
type DetectRequest struct {
	V      string       `json:"v"`      // protocol version
	Action string       `json:"action"` // always "detect"
	Entry  LogEntryJSON `json:"entry"`
	State  IPViewJSON   `json:"state"`
}

// DetectResponse is read from detector plugin stdout.
// Returned only when Score > 0. Zero score = clean.
type DetectResponse struct {
	Score  int    `json:"score"`
	Module string `json:"module"`
	Reason string `json:"reason"`
}

// WriteRequest is sent to a sink plugin stdin.
// The plugin writes the event to its configured destination and optionally returns WriteAck.
type WriteRequest struct {
	V      string          `json:"v"`      // protocol version
	Action string          `json:"action"` // always "write"
	Event  ThreatEventJSON `json:"event"`
}

// WriteAck is optionally returned by sink plugins after writing.
// If absent, the write is assumed to have succeeded.
type WriteAck struct {
	OK bool `json:"ok"`
}

// ExecuteRequest is sent to an executor plugin stdin.
// The plugin executes the action and returns ExecuteResponse.
type ExecuteRequest struct {
	V      string          `json:"v"`      // protocol version
	Action string          `json:"action"` // always "execute"
	Event  ThreatEventJSON `json:"event"`
}

// ExecuteResponse is read from executor plugin stdout.
// OK indicates whether the action was successfully executed.
// Error contains details when OK is false. If Error is empty, the execution succeeded.
type ExecuteResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// StartRequest is sent to a source plugin stdin to begin streaming.
// The plugin should start reading its source and emit SourceEntry messages.
type StartRequest struct {
	V      string `json:"v"`      // protocol version
	Action string `json:"action"` // always "start"
}

// StopRequest is sent to a source plugin stdin to stop streaming.
// The plugin should gracefully close its source and terminate.
type StopRequest struct {
	V      string `json:"v"`      // protocol version
	Action string `json:"action"` // always "stop"
}

// SourceEntry is one log line emitted by a source plugin stdout.
// Sent as NDJSON after StartRequest. Plugin closes stdout when done.
type SourceEntry struct {
	Entry LogEntryJSON `json:"entry"`
}

// logEntryToJSON converts a plugin.LogEntry to wire format for JSON transport.
// Called from: Detector.SendRequest, Source.SendStart. Non-blocking.
func logEntryToJSON(e *plugin.LogEntry) LogEntryJSON {
	return LogEntryJSON{
		RemoteAddr: e.RemoteAddr,
		RemoteUser: e.RemoteUser,
		Time:       e.Time.Format(time.RFC3339),
		Method:     e.Method,
		RawURI:     e.RawURI,
		Path:       e.Path,
		Query:      e.Query,
		Protocol:   e.Protocol,
		Status:     e.Status,
		BytesSent:  e.BytesSent,
		Referer:    e.Referer,
		UserAgent:  e.UserAgent,
		RealIP:     e.RealIP,
	}
}

// logEntryFromJSON converts wire format back to plugin.LogEntry.
// Time parsing failure returns a zero-valued time with error suppression
// to ensure robust recovery from malformed timestamps.
// Called from: Detector.SendRequest, Source.run. Non-blocking.
func logEntryFromJSON(j LogEntryJSON) *plugin.LogEntry {
	t, _ := time.Parse(time.RFC3339, j.Time)
	return &plugin.LogEntry{
		RemoteAddr: j.RemoteAddr,
		RemoteUser: j.RemoteUser,
		Time:       t,
		Method:     j.Method,
		RawURI:     j.RawURI,
		Path:       j.Path,
		Query:      j.Query,
		Protocol:   j.Protocol,
		Status:     j.Status,
		BytesSent:  j.BytesSent,
		Referer:    j.Referer,
		UserAgent:  j.UserAgent,
		RealIP:     j.RealIP,
	}
}

// threatEventToJSON converts a plugin.ThreatEvent to wire format.
func threatEventToJSON(e plugin.ThreatEvent) ThreatEventJSON {
	return ThreatEventJSON{
		Timestamp:  e.Timestamp.Format(time.RFC3339),
		Level:      e.Level,
		Stream:     e.Stream,
		Source:     e.Source,
		SourceType: e.SourceType,
		IP:         e.IP,
		Score:      e.Score,
		Modules:    e.Modules,
		Reason:     e.Reason,
		RawLine:    e.RawLine,
	}
}

// ipViewToJSON captures a point-in-time snapshot of plugin.IPView state.
// ApproxRate is computed over a 1-minute window.
func ipViewToJSON(sv plugin.IPView) IPViewJSON {
	// If RecentPaths() returns nil, initialize empty slice for JSON serialization
	// (nil slices serialize as null in JSON, which breaks plugin compatibility).
	recentPaths := sv.RecentPaths()
	if recentPaths == nil {
		recentPaths = []string{}
	}

	return IPViewJSON{
		IP:            sv.GetIP(),
		TotalRequests: sv.GetTotalRequests(),
		Requests404:   sv.GetRequests404(),
		RecentPaths:   recentPaths,
		ApproxRate:    sv.ApproxRate(time.Minute),
	}
}

// MarshalJSON helpers for DetectResponse, WriteAck, and other types
// are implicit via struct tags; JSON marshaling is handled by encoding/json.

// ParseDetectResponse parses a JSON response from a detector plugin.
// Returns an error if JSON is malformed.
// Called from: Detector.SendRequest. Non-blocking.
func ParseDetectResponse(data []byte) (DetectResponse, error) {
	var resp DetectResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}

// ParseWriteAck parses an optional JSON ack from a sink plugin.
// Returns an error if JSON is malformed. Absence of ack is not an error
// — the caller should assume OK if no response is sent.
// Called from: Sink.SendRequest. Non-blocking.
func ParseWriteAck(data []byte) (WriteAck, error) {
	var ack WriteAck
	err := json.Unmarshal(data, &ack)
	return ack, err
}

// ParseSourceEntry parses a JSON source entry from a source plugin.
func ParseSourceEntry(data []byte) (SourceEntry, error) {
	var entry SourceEntry
	err := json.Unmarshal(data, &entry)
	return entry, err
}

// ParseExecuteResponse parses a JSON response from an executor plugin.
// Returns an error if JSON is malformed.
func ParseExecuteResponse(data []byte) (ExecuteResponse, error) {
	var resp ExecuteResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}
