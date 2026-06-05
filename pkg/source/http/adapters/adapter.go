// ====== Module: HTTP Adapters Interface ======
// Defines the contract for protocol-specific log adapters.
// Each adapter implements Decode() for parsing vendor formats and WriteAck() for responses.

package adapters

import nethttp "net/http"

// Adapter is the interface implemented by all protocol adapters.
// Called from: buildPushHandler() and runPull() to parse vendor log formats.
type Adapter interface {
	// Decode parses vendor-specific HTTP body into generic log records.
	// Returns error if body is malformed or incompatible with protocol.
	Decode(body []byte) ([]EnvelopeRecord, error)
	// WriteAck writes protocol-specific acknowledgment response to HTTP client.
	// Called after successful Decode() to confirm receipt.
	WriteAck(w nethttp.ResponseWriter, meta map[string]string)
}

// EnvelopeRecord represents a parsed log entry from vendor HTTP payload.
// Contains raw log line, normalized timestamp, and vendor metadata.
type EnvelopeRecord struct {
	RawLine   string            // The parsed log line (e.g., message field content)
	Timestamp int64             // Unix nanoseconds — normalized from vendor format
	Metadata  map[string]string // Vendor-specific fields (request IDs, zones, etc.)
}
