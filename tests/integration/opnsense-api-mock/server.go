// ====== Module: opnsense-api-mock ======
//
//	OPNsense REST API mock server for integration tests.
//	Emulates the /api/firewall/alias_util/{add,delete,list} endpoints
//	used by the opnsense executor (pkg/executorplugins/opnsense/client.go).
//	HTTP Basic Auth is enforced; credentials are read from ENV variables
//	OPNSENSE_MOCK_API_KEY / OPNSENSE_MOCK_API_SECRET with sensible
//	test defaults ("testkey" / "testsecret").
//
//	Wire format (must match HTTPClient.doRequest / parseListEntries):
//	  POST /api/firewall/alias_util/add/{alias}    body {"address":"1.2.3.4"}
//	    -> 200 {"result":"saved"}      on success
//	    -> 401                          on bad Basic Auth
//	    -> 400                          on missing/invalid address
//	  POST /api/firewall/alias_util/delete/{alias} body {"address":"1.2.3.4"}
//	    -> 200 {"result":"saved"}      on success (no error if absent)
//	    -> 401                          on bad Basic Auth
//	    -> 400                          on missing/invalid address
//	  GET  /api/firewall/alias_util/list/{alias}
//	    -> 200 {"content":"ip1\nip2\n..."}  (newline-joined, exact match for
//	                                         the dominant OPNsense shape that
//	                                         parseListEntries splits on \n)
//
//	Test helpers (NOT part of the real OPNsense API):
//	  GET  /recorded-items -> {entries, add_calls, del_calls, list_calls}
//	  POST /reset          -> clears in-memory alias state and call counters.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// ========================== Constants ==========================

// default API credentials used when the corresponding ENV variables are
// not set. Kept in sync with the arxsentinel/opnsense-executor.yaml
// integration test config.
const (
	defaultAPIKey    = "testkey"
	defaultAPISecret = "testsecret"

	listenAddr = ":8080"
)

// ========================== MockServer ==========================

// MockServer is the in-memory backing store for one OPNsense alias.
// The real OPNsense keeps the alias' content on the firewall; here we
// keep it as a flat []string with a single global mutex so concurrent
// add/delete/list calls remain race-free. Per-alias locking is
// unnecessary — alias_util in the real product is itself a single
// endpoint surface.
type MockServer struct {
	mu        sync.Mutex
	entries   []string
	addCalls  atomic.Int64
	delCalls  atomic.Int64
	listCalls atomic.Int64
	apiKey    string
	apiSecret string
}

// newMockServer resolves the Basic Auth credentials from ENV
// (OPNSENSE_MOCK_API_KEY / OPNSENSE_MOCK_API_SECRET), falling back to
// the constants above. Centralised so tests can swap credentials by
// setting ENV before the binary starts.
func newMockServer() *MockServer {
	key := os.Getenv("OPNSENSE_MOCK_API_KEY")
	if key == "" {
		key = defaultAPIKey
	}
	secret := os.Getenv("OPNSENSE_MOCK_API_SECRET")
	if secret == "" {
		secret = defaultAPISecret
	}
	return &MockServer{
		apiKey:    key,
		apiSecret: secret,
	}
}

// ========================== main ==========================

func main() {
	mux := http.NewServeMux()
	s := newMockServer()

	// OPNsense alias_util endpoints. The {alias} path segment is part
	// of the URL itself (e.g. /api/firewall/alias_util/add/my_alias)
	// so we register an explicit handler that dispatches on the
	// trailing path components.
	mux.HandleFunc("/api/firewall/alias_util/add/", s.handleAdd)
	mux.HandleFunc("/api/firewall/alias_util/delete/", s.handleDelete)
	mux.HandleFunc("/api/firewall/alias_util/list/", s.handleList)

	// Test helpers — NOT part of the real OPNsense API.
	mux.HandleFunc("/recorded-items", s.handleRecordedItems)
	mux.HandleFunc("/reset", s.handleReset)

	log.Printf("opnsense-api-mock listening on %s (key=%q)", listenAddr, s.apiKey)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// ========================== Auth ==========================

// authenticate checks the request's Basic Auth header against the
// configured key/secret. Returns true on match, false on mismatch
// (and writes a 401 response in the latter case so the caller can
// just `return`).
//
// Uses crypto/subtle.ConstantTimeCompare to avoid leaking credential
// length / content through timing — the real OPNsense does the same
// indirectly via PHP's hash_equals, and we have no reason to weaken
// it in a mock.
func (s *MockServer) authenticate(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="opnsense"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}

	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.apiKey)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.apiSecret)) == 1
	if !userMatch || !passMatch {
		w.Header().Set("WWW-Authenticate", `Basic realm="opnsense"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// ========================== Path helpers ==========================

// aliasFromPath extracts the {alias} segment from a path like
// "/api/firewall/alias_util/add/my_alias". Returns the empty string
// and writes a 400 response when the segment is missing — the
// executor never calls alias_util without an alias, but defensive
// handling keeps the mock useful for ad-hoc curl tests.
func aliasFromPath(w http.ResponseWriter, prefix, path string) string {
	alias := strings.TrimPrefix(path, prefix)
	alias = strings.Trim(alias, "/")
	if alias == "" {
		http.Error(w, "bad request: missing alias name", http.StatusBadRequest)
		return ""
	}
	return alias
}

// ========================== Handlers ==========================

// handleAdd — POST /api/firewall/alias_util/add/{alias}.
//
//	Decode {"address":"1.2.3.4"}, append to s.entries (idempotent —
//	the real OPNsense deduplicates via the alias' unique-content
//	constraint; we mirror that with a membership check to keep
//	recorded-items output stable for repeated add calls), reply
//	{"result":"saved"}.
func (s *MockServer) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authenticate(w, r) {
		return
	}
	if alias := aliasFromPath(w, "/api/firewall/alias_util/add/", r.URL.Path); alias == "" {
		return
	}

	var body struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Address == "" {
		http.Error(w, "bad request: missing address", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	for _, e := range s.entries {
		if e == body.Address {
			s.mu.Unlock()
			s.addCalls.Add(1)
			writeResult(w, "saved")
			return
		}
	}
	s.entries = append(s.entries, body.Address)
	s.mu.Unlock()

	s.addCalls.Add(1)
	writeResult(w, "saved")
}

// handleDelete — POST /api/firewall/alias_util/delete/{alias}.
//
//	Decode {"address":"1.2.3.4"}, remove from s.entries. The real
//	OPNsense does not error when the address is already absent; we
//	mirror that — delete is idempotent. Reply {"result":"saved"}.
func (s *MockServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authenticate(w, r) {
		return
	}
	if alias := aliasFromPath(w, "/api/firewall/alias_util/delete/", r.URL.Path); alias == "" {
		return
	}

	var body struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Address == "" {
		http.Error(w, "bad request: missing address", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	filtered := s.entries[:0]
	for _, e := range s.entries {
		if e != body.Address {
			filtered = append(filtered, e)
		}
	}
	s.entries = filtered
	s.mu.Unlock()

	s.delCalls.Add(1)
	writeResult(w, "saved")
}

// handleList — GET /api/firewall/alias_util/list/{alias}.
//
//	Return {"content":"ip1\nip2\n..."} — exactly the shape that
//	parseListEntries in pkg/executorplugins/opnsense/client.go splits
//	on '\n'. Empty alias -> empty content (not missing field) so the
//	parser's `resp.Content == ""` branch is exercised correctly.
func (s *MockServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authenticate(w, r) {
		return
	}
	if alias := aliasFromPath(w, "/api/firewall/alias_util/list/", r.URL.Path); alias == "" {
		return
	}

	s.mu.Lock()
	snapshot := make([]string, len(s.entries))
	copy(snapshot, s.entries)
	s.mu.Unlock()

	s.listCalls.Add(1)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"content": strings.Join(snapshot, "\n"),
	})
}

// writeResult writes the standard OPNsense result envelope. Centralised
// so add and delete stay byte-for-byte identical.
func writeResult(w http.ResponseWriter, result string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// ========================== Test helpers ==========================

// handleRecordedItems (GET /recorded-items) — return the snapshot of
// the alias state and every call counter so integration tests can
// assert on observable side-effects. Mirrors the structure used by
// ubus-api-mock for consistency across the mock family.
func (s *MockServer) handleRecordedItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	entriesCopy := make([]string, len(s.entries))
	copy(entriesCopy, s.entries)
	s.mu.Unlock()

	out := struct {
		Entries   []string `json:"entries"`
		AddCalls  int64    `json:"add_calls"`
		DelCalls  int64    `json:"del_calls"`
		ListCalls int64    `json:"list_calls"`
	}{
		Entries:   entriesCopy,
		AddCalls:  s.addCalls.Load(),
		DelCalls:  s.delCalls.Load(),
		ListCalls: s.listCalls.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleReset (POST /reset) — drop all in-memory alias state and zero
// every counter so the next scenario starts from a clean slate.
func (s *MockServer) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	s.entries = nil
	s.mu.Unlock()

	s.addCalls.Store(0)
	s.delCalls.Store(0)
	s.listCalls.Store(0)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}
