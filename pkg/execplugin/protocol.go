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

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ProtoVersion is the protocol version number. Used for future compatibility checks.
const ProtoVersion = "1"

// LogEntryJSON is the wire representation of plugin.LogEntry for JSON transport.
// Flat struct mirrors plugin.LogEntry field-by-field to avoid requiring
// external plugin authors to import internal packages.
type LogEntryJSON struct {
	RemoteAddr string `json:"remote_addr"`
	RemoteUser string `json:"remote_user"`
	Time       string `json:"time"` // RFC3339
	Method     string `json:"method"`
	RawURI     string `json:"raw_uri"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	Protocol   string `json:"protocol"`
	Status     int    `json:"status"`
	BytesSent  int64  `json:"bytes_sent"`
	Referer    string `json:"referer"`
	UserAgent  string `json:"user_agent"`
	RealIP     string `json:"real_ip"`
}

// IPViewJSON is the wire representation of plugin.IPView for JSON transport.
// Captures a point-in-time snapshot of per-IP state.
type IPViewJSON struct {
	IP            string   `json:"ip"`
	TotalRequests int      `json:"total_requests"`
	Requests404   int      `json:"requests_404"`
	RecentPaths   []string `json:"recent_paths"`
	ApproxRate    float64  `json:"approx_rate_1m"` // requests/second over 1 minute window
}

// ThreatEventJSON is the wire representation of plugin.ThreatEvent for JSON transport.
// Includes all fields needed to route the event to external systems.
type ThreatEventJSON struct {
	Timestamp  string   `json:"timestamp"` // RFC3339
	Level      string   `json:"level"`
	Stream     string   `json:"stream"`
	Source     string   `json:"source"`
	SourceType string   `json:"source_type"`
	IP         string   `json:"ip"`
	Score      int      `json:"score"`
	Modules    []string `json:"modules"`
	Reason     string   `json:"reason"`
	RawLine    string   `json:"raw_line,omitempty"` // omit if empty
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
func ParseDetectResponse(data []byte) (DetectResponse, error) {
	var resp DetectResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}

// ParseWriteAck parses an optional JSON ack from a sink plugin.
// Returns an error if JSON is malformed. Absence of ack is not an error
// — the caller should assume OK if no response is sent.
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
